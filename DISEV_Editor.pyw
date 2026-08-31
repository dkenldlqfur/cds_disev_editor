#!/usr/bin/env python3
"""Safe visual editor for the DISEV.CDS LS12 event archive.

Version 0.1 deliberately keeps each condition/body chunk at its original byte
length.  That makes byte edits safe without having to guess every branch
opcode and relocate unknown jump targets.  Modified parts are stored
uncompressed; untouched compressed payloads remain byte-for-byte identical.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import ctypes  # Win32 네이티브 EDIT 컨트롤용; DPI 설정에는 사용하지 않는다.
import tkinter as tk
import tkinter.font as tkfont
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import dump_disev as disev


def _resource_data_dirs() -> tuple[Path, ...]:
    """개발 폴더와 배포 폴더에서 공용 JSON 데이터 위치를 차례로 찾는다."""
    project_dir = Path(__file__).resolve().parent
    return (
        project_dir / "Resources" / "data",
        project_dir.parent / "Resources" / "data",
        project_dir.parent / "cds_save_editor" / "Resources" / "data",
    )


def _resource_data_dir() -> Path:
    return next((path for path in _resource_data_dirs() if path.is_dir()), _resource_data_dirs()[0])


def _load_ui_texts() -> dict[str, str]:
    """UI 문구 JSON을 읽는다. 누락 시에는 개발 중 원인을 바로 드러낸다."""
    path = _resource_data_dir() / "ui_texts.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {str(key): str(value) for key, value in data["texts"].items()}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(f"UI 문자열 파일을 읽을 수 없습니다: {path}") from exc


UI_TEXTS = _load_ui_texts()


def ui(key: str, *args: object) -> str:
    """키 기반 UI 문구를 반환한다."""
    text = UI_TEXTS[key]
    return text.format(*args) if args else text


def _load_app_config() -> dict[str, object]:
    """DISEV 편집기 리소스의 앱 설정을 읽는다."""
    path = _resource_data_dir() / "app_config.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            return value
    except (OSError, ValueError):
        pass
    return {}


APP_CONFIG = _load_app_config()
APP_VERSION = str(APP_CONFIG.get("version", "0.0")).strip() or "0.0"
APP_TITLE = f"{ui('app_title')} v{APP_VERSION}"
UPDATE_CONFIG = APP_CONFIG.get("update", {})
UPDATE_CONFIG = UPDATE_CONFIG if isinstance(UPDATE_CONFIG, dict) else {}
UPDATE_REPOSITORY = str(UPDATE_CONFIG.get("repository", "")).strip()
UPDATE_ASSET_NAME = str(UPDATE_CONFIG.get("asset_name", "DISEV_Editor_v{version}.zip")).strip()
UPDATE_EXECUTABLE_NAME = "DISEV_Editor.exe"
UPDATE_LATEST_URL = (f"https://api.github.com/repos/{UPDATE_REPOSITORY}/releases/latest"
                     if UPDATE_REPOSITORY else "")
UPDATE_RELEASES_URL = (f"https://api.github.com/repos/{UPDATE_REPOSITORY}/releases?per_page=100"
                       if UPDATE_REPOSITORY else "")
UPDATE_HISTORY_MIN_VERSION = (0, 1, 0)


def parse_release_version(value: object) -> tuple[int, int, int] | None:
    """Release 태그를 비교 가능한 세 자리 버전으로 바꾼다."""
    pieces = str(value).strip().lstrip("vV").split(".")
    if not 1 <= len(pieces) <= 3 or not all(piece.isdigit() for piece in pieces):
        return None
    return tuple(int(piece) for piece in (*pieces, "0", "0")[:3])

def _theme_settings_path() -> Path:
    """두 편집기가 공유하는 사용자별 UI 설정 파일 경로다."""
    return Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CDS_SaveEditor" / "ui_settings.json"


def _load_saved_theme(setting_key: str, available_themes: tuple[str, ...]) -> str | None:
    try:
        theme = json.loads(_theme_settings_path().read_text(encoding="utf-8")).get(setting_key)
        return theme if theme in available_themes else None
    except (OSError, ValueError, TypeError):
        return None


def _save_theme(setting_key: str, theme: str) -> None:
    path = _theme_settings_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError, TypeError):
            data = {}
        data[setting_key] = theme
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


OPCODE_GUIDE = ui("opcode_guide")


# 조건 빌더는 EXE의 조건 인터프리터에서 의미와 피연산자 형식이 확인된 항목만 노출한다.
# 한 파트의 조건 덩이는 본문 앞에 독립적으로 놓이므로, 이 목록에서 고른 조건은 길이가
# 바뀌어도 슬롯의 본문 오프셋만 다시 기록하면 안전하다.
CONDITION_KINDS = {
    "항상 실행": ((), lambda values: b""),
    "국가": ((("국가 ID", 0, 65535),), lambda v: b"\x17\x00" + struct.pack("<H", v[0])),
    "도시": ((("도시 ID", 0, 65535),), lambda v: b"\x17\x08" + struct.pack("<H", v[0])),
    "건물": ((("건물 ID", 0, 65535),), lambda v: b"\x17\x10" + struct.pack("<H", v[0])),
    "문화권": ((("문화권 ID", 0, 65535),), lambda v: b"\x17\x19" + struct.pack("<H", v[0])),
    "아이템 소지": ((("아이템 ID", 0, 65535),), lambda v: b"\x12\x05" + struct.pack("<H", v[0])),
    "아이템 비소지": ((("아이템 ID", 0, 65535),), lambda v: b"\x0F\x05" + struct.pack("<H", v[0])),
    "힌트 상태 활성": ((("힌트 상태 ID", 0, 65535),), lambda v: b"\x0F\x0E" + struct.pack("<H", v[0])),
    "힌트 상태 미활성": ((("힌트 상태 ID", 0, 65535),), lambda v: b"\x12\x0E" + struct.pack("<H", v[0])),
    "기준 연도 이후": ((("연도", 0, 65535),), lambda v: b"\x1B\x16" + struct.pack("<H", v[0])),
    "기준 연도 이전": ((("연도", 0, 65535),), lambda v: b"\x1C\x16" + struct.pack("<H", v[0])),
    "특정 연·월": (
        (("월", 1, 12), ("연도", 0, 65535)),
        lambda v: b"\x1B\x17" + bytes((v[0],)) + b"\x16" + struct.pack("<H", v[1]),
    ),
    "연도 범위": (
        (("시작 연도", 0, 65535), ("종료 연도", 0, 65535)),
        lambda v: b"\x36\x16" + struct.pack("<H", v[0]) + b"\x16" + struct.pack("<H", v[1]),
    ),
    # 2E가 두 피연산자를 모두 고정값(1A)으로 받을 때 EXE는 Random(분모) < 성공값을 검사한다.
    "무작위 확률": (
        (("분모", 1, 0xFFFFFFFF),),
        lambda v: b"\x2E\x1A" + struct.pack("<I", v[0]) + b"\x1A\x01\x00\x00\x00",
    ),
    # 37은 하위 타입에 따라 서로 다른 런타임 객체 표를 선택한다.
    # 조건 종류를 분리해 대상 종류를 다시 고를 필요가 없게 한다.
    "인물 조건": ((), lambda v: b"\x37\x0D" + struct.pack("<H", v[0])),
    "후원자 조건": ((), lambda v: b"\x37\x12" + struct.pack("<H", v[0])),
    "후원자 계약 없음": ((), lambda values: b"\x5A"),
    "또는 (OR)": ((), lambda values: b"\x50"),
}

# 편집기는 바이트코드의 세부 조건을 보존하되, UI에서는 상위 분류와 하위 분류로 묶는다.
CONDITION_GROUPS: dict[str, tuple[str, ...]] = {
    "항상 실행": (),
    "위치": ("국가", "도시", "건물", "문화권"),
    "아이템": ("소지", "미소지"),
    "힌트 상태": ("활성", "비활성"),
    "기준 연도": ("이후", "이전"),
    "특정 연·월": (),
    "연도 범위": (),
    "무작위 확률": (),
    "NPC": ("인물", "후원자"),
    "후원자 계약 없음": (),
    "또는 (OR)": (),
}
CONDITION_GROUP_TO_KIND = {
    ("위치", "국가"): "국가", ("위치", "도시"): "도시", ("위치", "건물"): "건물", ("위치", "문화권"): "문화권",
    ("아이템", "소지"): "아이템 소지", ("아이템", "미소지"): "아이템 비소지",
    ("힌트 상태", "활성"): "힌트 상태 활성", ("힌트 상태", "비활성"): "힌트 상태 미활성",
    ("기준 연도", "이후"): "기준 연도 이후", ("기준 연도", "이전"): "기준 연도 이전",
    ("NPC", "인물"): "인물 조건", ("NPC", "후원자"): "후원자 조건",
}
CONDITION_KIND_TO_GROUP = {kind: group for group, kind in CONDITION_GROUP_TO_KIND.items()}

BODY_COMMAND_KINDS = (
    "대사", "예/아니오 대사", "다중 선택지 대사", "대상 지정 대사", "AVI 재생", "발견물 등록/발견 처리", "아이템 획득", "아이템 상실", "이벤트 아이템 등록", "이벤트 아이템 처리",
    "음원 재생", "음원 정지", "DSTILL 이미지 표시", "EVSTILL 이미지 표시", "CG 애니메이션 재생", "특수 조우 연출 설정", "특수 수치 판정", "해상 전투", "인물 이벤트 실행", "인물 이벤트 실행 (보조)", "이벤트 분류 설정", "이벤트 조건 판정", "이벤트 내부 참조", "주인공 성격 판정", "이벤트 판정", "힌트 획득", "대기", "날짜 경과", "발견물 이름 설정",
    "신도시 생성",
    "이미지 표시 종료", "대화창 숨김", "대화창 표시", "결과 거짓 설정", "결과 참 설정", "결과 거짓 시 이동", "결과 참 시 이동", "이전 조건 참 시 이동", "특수 분기", "선택지 결과 시 이동", "힌트 상태 조건 이동", "발견물 상태 조건 이동", "발견물 등록 판정 이동", "아이템 소지 조건 이동", "아이템 미소지 조건 이동", "기준 연도 조건 이동", "연도 상한 조건 이동", "연도 범위 조건 이동", "도시 조건 이동", "NPC 조건 이동", "상태값 초과 조건 이동", "상태값 초과 조건 이동 (고정 기준)", "상태값 미만 조건 이동", "상태값 이하 조건 이동", "상태값 미만 조건 이동 (무작위 기준)", "상태값 이하 조건 이동 (무작위 기준)", "능력치 비교 분기", "능력치 비교3 분기", "상태값 참조 비교 조건 이동", "상태값 특수 비교 조건 이동", "소지금 비교 분기", "특수 참조 조건 이동", "STORY0.CDS 외 분기", "STORY1.CDS 외 분기",
    "소지금 증가", "소지금 감소", "이벤트 플래그 설정",
    "상태값 증감", "상태값 설정", "상태값 참조 증가", "내부 상태 설정", "특수 상태 처리", "인물 참조 설정", "인물 상태 처리 1", "인물 상태 처리 2", "인물 상태 처리 3", "인물 상태 처리 4", "인물 상태 비트 해제", "인물 선택 판정", "인물 위치 판정", "이벤트 결과 코드",
)
DIALOGUE_KINDS = ("대사", "예/아니오 대사", "다중 선택지 대사", "대상 지정 대사")
CHARACTER_TARGET_COMMAND_KINDS = (
    "인물 참조 설정", "인물 상태 처리 1", "인물 상태 처리 2", "인물 상태 처리 3", "인물 상태 처리 4", "인물 상태 비트 해제", "인물 선택 판정", "인물 위치 판정",
)
BODY_COMMAND_GROUPS: dict[str, tuple[str, ...]] = {
    "발견": (),
    "아이템": ("획득", "상실"),
    "음원": ("재생", "정지"),
    "미디어": ("이미지", "동영상"),
    "대사": ("일반", "예/아니오", "다중 선택", "대상 지정"),
    "이벤트 아이템": ("등록", "처리"), "특수 조우 연출 설정": (), "특수 수치 판정": (),
    "해상 전투": (), "인물 이벤트 실행": (), "인물 이벤트 실행 (보조)": (), "이벤트 분류 설정": (),
    "이벤트 조건 판정": (), "이벤트 내부 참조": (), "주인공 성격 판정": (), "이벤트 판정": (), "힌트 획득": (),
    "대기": (), "날짜 경과": (), "발견물 이름 설정": (), "신도시 생성": (), "대화창": ("숨김", "표시"),
    "결과 설정": ("거짓", "참"),
    "행 이동": ("이전 조건", "이전 판정 참", "특수 분기", "선택지 결과", "힌트 상태", "발견물", "아이템 상태", "기준 연도", "연도 상한", "연도 범위", "도시 조건", "NPC 조건", "상태값"),
    "상태값": ("증감", "설정", "증감 (상태값 참조)"), "인물 상태": ("참조 설정", "처리 1", "처리 2", "처리 3", "처리 4", "비트 해제", "선택 판정", "위치 판정"), "소지금": ("증가", "감소", "비교 분기"), "외부 분기": ("STORY0.CDS", "STORY1.CDS"), "이벤트 플래그 설정": (),
    "내부 상태 설정": (), "특수 상태 처리": (), "이벤트 결과 코드": (),
}
BODY_GROUP_TO_KIND = {
    ("발견", ""): "발견물 등록/발견 처리",
    ("아이템", "획득"): "아이템 획득", ("아이템", "상실"): "아이템 상실",
    ("이벤트 아이템", "등록"): "이벤트 아이템 등록", ("이벤트 아이템", "처리"): "이벤트 아이템 처리",
    ("음원", "재생"): "음원 재생", ("음원", "정지"): "음원 정지",
    ("미디어", "DSTILL"): "DSTILL 이미지 표시", ("미디어", "EVSTILL"): "EVSTILL 이미지 표시",
    ("미디어", "종료"): "이미지 표시 종료", ("미디어", "CG"): "CG 애니메이션 재생", ("미디어", "AVI"): "AVI 재생",
    ("대사", "일반"): "대사", ("대사", "예/아니오"): "예/아니오 대사", ("대사", "다중 선택"): "다중 선택지 대사", ("대사", "대상 지정"): "대상 지정 대사",
    ("발견물 이름 설정", ""): "발견물 이름 설정",
    ("상태값", "증감"): "상태값 증감", ("상태값", "설정"): "상태값 설정",
    ("상태값", "증감 (상태값 참조)"): "상태값 참조 증가",
    ("인물 상태", "참조 설정"): "인물 참조 설정", ("인물 상태", "처리 1"): "인물 상태 처리 1", ("인물 상태", "처리 2"): "인물 상태 처리 2", ("인물 상태", "처리 3"): "인물 상태 처리 3", ("인물 상태", "처리 4"): "인물 상태 처리 4", ("인물 상태", "비트 해제"): "인물 상태 비트 해제", ("인물 상태", "선택 판정"): "인물 선택 판정", ("인물 상태", "위치 판정"): "인물 위치 판정",
    ("소지금", "증가"): "소지금 증가", ("소지금", "감소"): "소지금 감소",
    ("소지금", "비교 분기"): "소지금 비교 분기",
    ("외부 분기", "STORY0.CDS"): "STORY0.CDS 외 분기", ("외부 분기", "STORY1.CDS"): "STORY1.CDS 외 분기",
    ("대화창", "숨김"): "대화창 숨김", ("대화창", "표시"): "대화창 표시",
    ("결과 설정", "거짓"): "결과 거짓 설정", ("결과 설정", "참"): "결과 참 설정",
    ("행 이동", "이전 판정 참"): "이전 조건 참 시 이동", ("행 이동", "특수 분기"): "특수 분기",
    ("행 이동", "선택지 결과"): "선택지 결과 시 이동", ("행 이동", "힌트 상태"): "힌트 상태 조건 이동",
    ("행 이동", "도시 조건"): "도시 조건 이동",
    ("행 이동", "연도 범위"): "연도 범위 조건 이동",
    ("행 이동", "기준 연도"): "기준 연도 조건 이동",
    ("행 이동", "연도 상한"): "연도 상한 조건 이동",
    ("행 이동", "NPC 조건"): "NPC 조건 이동",
}
BODY_KIND_TO_GROUP = {kind: group for group, kind in BODY_GROUP_TO_KIND.items()}
MEDIA_SUBKINDS: dict[str, tuple[str, ...]] = {
    "이미지": ("DSTILL", "EVSTILL", "종료"),
    "동영상": ("CG", "AVI"),
}
MEDIA_DETAIL_TO_KIND = {
    ("이미지", "DSTILL"): "DSTILL 이미지 표시",
    ("이미지", "EVSTILL"): "EVSTILL 이미지 표시",
    ("이미지", "종료"): "이미지 표시 종료",
    ("동영상", "CG"): "CG 애니메이션 재생",
    ("동영상", "AVI"): "AVI 재생",
}
MOVE_SUBKINDS: dict[str, tuple[str, ...]] = {
    "이전 조건": ("거짓", "참"),
    "힌트 상태": ("활성", "미활성"),
    "아이템 상태": ("소지", "미소지"),
    "발견물": ("상태", "등록"),
    "상태값": ("초과 (랜덤)", "초과 (고정)", "미만", "이하", "이하 (수치)", "초과 (수치)", "상태값끼리 비교", "같음 (수치)", "특수 참조"),
}
MOVE_DETAIL_TO_KIND = {
    ("이전 조건", "거짓"): "결과 거짓 시 이동",
    ("이전 조건", "참"): "결과 참 시 이동",
    ("힌트 상태", "활성"): "힌트 상태 조건 이동",
    ("힌트 상태", "미활성"): "힌트 상태 조건 이동",
    ("아이템 상태", "소지"): "아이템 소지 조건 이동",
    ("아이템 상태", "미소지"): "아이템 미소지 조건 이동",
    ("발견물", "상태"): "발견물 상태 조건 이동",
    ("발견물", "등록"): "발견물 등록 판정 이동",
    ("상태값", "초과 (랜덤)"): "상태값 초과 조건 이동",
    ("상태값", "초과 (고정)"): "상태값 초과 조건 이동 (고정 기준)",
    ("상태값", "미만"): "상태값 미만 조건 이동",
    ("상태값", "이하"): "상태값 이하 조건 이동",
    ("상태값", "이하 (수치)"): "능력치 비교 분기",
    ("상태값", "초과 (수치)"): "능력치 비교3 분기",
    ("상태값", "상태값끼리 비교"): "상태값 참조 비교 조건 이동",
    ("상태값", "같음 (수치)"): "상태값 특수 비교 조건 이동",
    ("상태값", "특수 참조"): "특수 참조 조건 이동",
}
BODY_KIND_TO_GROUP.update({
    "DSTILL 이미지 표시": ("미디어", "이미지"),
    "EVSTILL 이미지 표시": ("미디어", "이미지"),
    "이미지 표시 종료": ("미디어", "이미지"),
    "CG 애니메이션 재생": ("미디어", "동영상"),
    "AVI 재생": ("미디어", "동영상"),
    "결과 거짓 시 이동": ("행 이동", "이전 조건"),
    "결과 참 시 이동": ("행 이동", "이전 조건"),
    "이전 조건 참 시 이동": ("행 이동", "이전 판정 참"),
    "특수 분기": ("행 이동", "특수 분기"),
    "선택지 결과 시 이동": ("행 이동", "선택지 결과"),
    "힌트 상태 조건 이동": ("행 이동", "힌트 상태"),
    "발견물 상태 조건 이동": ("행 이동", "발견물"),
    "발견물 등록 판정 이동": ("행 이동", "발견물"),
    "연도 범위 조건 이동": ("행 이동", "연도 범위"),
    "기준 연도 조건 이동": ("행 이동", "기준 연도"),
    "연도 상한 조건 이동": ("행 이동", "연도 상한"),
    "도시 조건 이동": ("행 이동", "도시 조건"),
    "NPC 조건 이동": ("행 이동", "NPC 조건"),
    "대화창 숨김": ("대화창", "숨김"),
    "대화창 표시": ("대화창", "표시"),
    "소지금 증가": ("소지금", "증가"),
    "소지금 감소": ("소지금", "감소"),
    "소지금 비교 분기": ("소지금", "비교 분기"),
    "STORY0.CDS 외 분기": ("외부 분기", "STORY0.CDS"),
    "STORY1.CDS 외 분기": ("외부 분기", "STORY1.CDS"),
    "인물 상태 처리 1": ("인물 상태", "처리 1"),
    "인물 상태 처리 2": ("인물 상태", "처리 2"),
    "인물 상태 처리 3": ("인물 상태", "처리 3"),
    "인물 참조 설정": ("인물 상태", "참조 설정"),
    "인물 상태 처리 4": ("인물 상태", "처리 4"),
    "인물 상태 비트 해제": ("인물 상태", "비트 해제"),
    "인물 선택 판정": ("인물 상태", "선택 판정"),
    "인물 위치 판정": ("인물 상태", "위치 판정"),
})
BODY_KIND_TO_DETAIL = {kind: detail for (_group, detail), kind in MEDIA_DETAIL_TO_KIND.items()}
BODY_KIND_TO_DETAIL.update({kind: detail for (_group, detail), kind in MOVE_DETAIL_TO_KIND.items()})
HINT_BRANCH_KIND = "힌트 상태 조건 이동"
DISCOVERY_BRANCH_KIND = "발견물 상태 조건 이동"
DISCOVERY_REGISTRATION_BRANCH_KIND = "발견물 등록 판정 이동"
YEAR_RANGE_BRANCH_KIND = "연도 범위 조건 이동"
YEAR_BRANCH_KIND = "기준 연도 조건 이동"
YEAR_UPPER_BRANCH_KIND = "연도 상한 조건 이동"
CITY_BRANCH_KIND = "도시 조건 이동"
NPC_BRANCH_KIND = "NPC 조건 이동"
ITEM_POSSESSION_BRANCH_KIND = "아이템 소지 조건 이동"
ITEM_ABSENCE_BRANCH_KIND = "아이템 미소지 조건 이동"
STATE_LESS_BRANCH_KIND = "상태값 미만 조건 이동"
STATE_LESS_OR_EQUAL_BRANCH_KIND = "상태값 이하 조건 이동"
STATE_GREATER_RANDOM_BRANCH_KIND = "상태값 초과 조건 이동"
STATE_GREATER_BRANCH_KIND = "상태값 초과 조건 이동 (고정 기준)"
STATE_LESS_RANDOM_BRANCH_KIND = "상태값 미만 조건 이동 (무작위 기준)"
STATE_LESS_OR_EQUAL_RANDOM_BRANCH_KIND = "상태값 이하 조건 이동 (무작위 기준)"
STATE_REFERENCE_COMPARE_BRANCH_KIND = "상태값 참조 비교 조건 이동"
ABILITY_COMPARE_BRANCH_KIND = "능력치 비교 분기"
ABILITY_COMPARE3_BRANCH_KIND = "능력치 비교3 분기"
STATE_SCALAR_COMPARE_BRANCH_KIND = "상태값 특수 비교 조건 이동"
RUNTIME_REFERENCE_BRANCH_KIND = "특수 참조 조건 이동"
RANDOM_STATE_COMPARE_BRANCH_KINDS = (STATE_GREATER_RANDOM_BRANCH_KIND, STATE_LESS_RANDOM_BRANCH_KIND, STATE_LESS_OR_EQUAL_RANDOM_BRANCH_KIND)
STATE_COMPARE_BRANCH_KINDS = (STATE_GREATER_BRANCH_KIND, STATE_LESS_BRANCH_KIND, STATE_LESS_OR_EQUAL_BRANCH_KIND) + RANDOM_STATE_COMPARE_BRANCH_KINDS
NUMERIC_COMPARE_BRANCH_KINDS = STATE_COMPARE_BRANCH_KINDS + (
    ABILITY_COMPARE_BRANCH_KIND,
    ABILITY_COMPARE3_BRANCH_KIND,
    STATE_SCALAR_COMPARE_BRANCH_KIND,
)
BODY_KIND_TO_GROUP.update({
    STATE_GREATER_RANDOM_BRANCH_KIND: ("행 이동", "상태값"),
    STATE_GREATER_BRANCH_KIND: ("행 이동", "상태값"),
    STATE_LESS_BRANCH_KIND: ("행 이동", "상태값"),
    STATE_LESS_OR_EQUAL_BRANCH_KIND: ("행 이동", "상태값"),
    STATE_LESS_RANDOM_BRANCH_KIND: ("행 이동", "상태값"),
    STATE_LESS_OR_EQUAL_RANDOM_BRANCH_KIND: ("행 이동", "상태값"),
    ABILITY_COMPARE_BRANCH_KIND: ("행 이동", "상태값"),
    ABILITY_COMPARE3_BRANCH_KIND: ("행 이동", "상태값"),
    STATE_REFERENCE_COMPARE_BRANCH_KIND: ("행 이동", "상태값"),
    ITEM_POSSESSION_BRANCH_KIND: ("행 이동", "아이템 상태"),
    ITEM_ABSENCE_BRANCH_KIND: ("행 이동", "아이템 상태"),
    STATE_SCALAR_COMPARE_BRANCH_KIND: ("행 이동", "상태값"),
    RUNTIME_REFERENCE_BRANCH_KIND: ("행 이동", "특수 참조"),
})
BODY_KIND_TO_DETAIL[STATE_REFERENCE_COMPARE_BRANCH_KIND] = "상태값끼리 비교"
BODY_KIND_TO_DETAIL[DISCOVERY_BRANCH_KIND] = "상태"
BODY_KIND_TO_DETAIL[DISCOVERY_REGISTRATION_BRANCH_KIND] = "등록"
BODY_KIND_TO_DETAIL[STATE_GREATER_BRANCH_KIND] = "초과 (고정)"
BODY_KIND_TO_DETAIL[ABILITY_COMPARE_BRANCH_KIND] = "이하 (수치)"
BODY_KIND_TO_DETAIL[ABILITY_COMPARE3_BRANCH_KIND] = "초과 (수치)"
BODY_KIND_TO_DETAIL[STATE_SCALAR_COMPARE_BRANCH_KIND] = "같음 (수치)"
BODY_KIND_TO_DETAIL[RUNTIME_REFERENCE_BRANCH_KIND] = "특수 참조"
CHOICE_BRANCH_KIND = "선택지 결과 시 이동"
EVENT_RESULT_CODES = (
    (0, "이벤트 종료"),
    (1, "다음 단계 진행"),
    (2, "이벤트 반복"),
)
EVENT_RESULT_NAMES = dict(EVENT_RESULT_CODES)

# 설명 탭에는 편집기에 실제로 노출하는 명령만 적는다. 16진 바이트열 대신
# 스크립트를 작성할 때 필요한 실행 의미를 바로 보여 준다.
COMMAND_GUIDE = (
    ("조건", "항상 실행", "조건 검사를 하지 않고 본문을 바로 실행합니다."),
    ("조건", "위치 | 국가·도시·건물·문화권", "1차 위치에서 2차 위치 종류와 대상을 선택합니다. 현재 위치가 해당 대상에 속하는지 검사합니다."),
    ("조건", "아이템 | 소지·미소지", "1차 아이템에서 2차 소지 또는 미소지를 선택한 뒤 대상 아이템을 지정합니다."),
    ("조건", "힌트 상태 | 활성·비활성", "1차 힌트 상태에서 2차 활성 또는 비활성을 선택한 뒤 힌트를 지정합니다."),
    ("조건", "기준 연도 | 이후·이전", "1차 기준 연도에서 2차 이후 또는 이전을 선택하고 기준 연도를 입력합니다."),
    ("조건", "특정 연·월 / 연도 범위", "특정 연·월은 월과 연도를, 연도 범위는 시작·종료 연도를 각각 입력해 검사합니다."),
    ("조건", "무작위 확률", "1 / 분모 확률로만 조건을 통과시킵니다."),
    ("조건", "NPC | 인물·후원자", "1차 NPC에서 2차 인물 또는 후원자를 선택한 뒤 대상을 지정합니다. 대상의 런타임 존재·활성 상태를 검사합니다."),
    ("조건", "후원자 계약 없음", "현재 후원자 계약이 없을 때만 통과합니다."),
    ("조건", "또는 (OR)", "양옆 조건 중 하나가 참이면 통과합니다. OR 없이 이어진 조건은 모두 참이어야 합니다."),
    ("본문", "대사 | 일반 | 화자", "1차 대사, 2차 일반, 3차 화자를 선택해 대사를 표시하고 확인 뒤 다음 행으로 진행합니다."),
    ("본문", "대사 | 예/아니오 | 화자", "예·아니오 선택 대사를 표시합니다. 선택 결과는 행 이동 | 이전 조건 | 참·거짓에서 사용합니다."),
    ("본문", "대사 | 다중 선택 | 화자", "슬래시(/)로 구분한 선택지를 표시합니다. 행 이동 | 선택지 결과에서 각 선택값을 처리합니다."),
    ("본문", "대사 | 대상 지정 | 화자", "화자와 대상 인물을 지정해 대사를 표시합니다."),
    ("본문", "음원 | 재생", "음원 ID를 재생합니다."),
    ("본문", "음원 | 정지", "현재 재생 중인 음원을 정지합니다."),
    ("본문", "미디어 | 이미지 | DSTILL", "DSTILL의 지정한 정지 이미지 번호를 표시합니다."),
    ("본문", "미디어 | 이미지 | EVSTILL", "EVSTILL의 지정한 이미지 번호를 표시합니다."),
    ("본문", "미디어 | 이미지 | 종료", "현재 표시 중인 이미지를 닫고 다음 명령으로 진행합니다."),
    ("본문", "미디어 | 동영상 | CG", "지정한 CG 애니메이션 번호를 재생합니다."),
    ("본문", "미디어 | 동영상 | AVI", "지정한 AVI 번호를 재생합니다."),
    ("본문", "특수 조우 연출 설정", "동물·자연현상·유령선 등 특수 조우 이벤트의 연출 종류를 지정합니다. 값별 세부 동작은 아직 실행 파일 추적이 필요합니다."),
    ("본문", "특수 수치 판정", "유적·함정 이벤트에서 판정값과 난이도로 내부 결과를 설정합니다. 정확한 성공 산식은 실행 파일 추적이 필요하며, 뒤의 결과 참·거짓 이동 명령이 결과를 사용합니다."),
    ("본문", "해상 전투", "지정한 해상 조우 상대와 전투를 시작합니다. 결과 참·거짓 시 이동 명령으로 승패 경로를 처리합니다."),
    ("본문", "이벤트 아이템 등록", "직전 획득한 아이템을 이벤트용으로 추가 등록합니다. 일반 아이템 획득 뒤에 같은 ID로 이어집니다."),
    ("본문", "이벤트 아이템 처리", "아이템 ID를 대상으로 이벤트 전용 처리를 실행합니다. 일반 획득과 상위 연산이 다르며, 세부 동작은 실행 파일 추적이 필요합니다."),
    ("본문", "인물 이벤트 실행", "인물 타입(ID) 기반의 이벤트 처리를 실행하고 결과를 후속 분기에서 사용합니다. 세부 동작은 실행 파일 추적이 필요합니다."),
    ("본문", "인물 이벤트 실행 (보조)", "인물 타입(ID) 기반의 보조 이벤트 처리를 실행합니다. 기본 실행 명령과 상위 연산이 달라 별도 보존합니다."),
    ("본문", "인물 상태 처리 1 / 2", "역사 인물 ID의 런타임 상태를 처리합니다. 처리 2는 현재 파일에서 처리 1 바로 앞에만 쓰입니다. 세부 상태 의미는 실행 파일 추적이 필요합니다."),
    ("본문", "이벤트 분류 설정", "유적·민족·인물 이벤트에서 쓰는 내부 분류값을 지정합니다. 현재 확인된 값은 1~4이며 세부 의미는 실행 파일 추적이 필요합니다."),
    ("본문", "이벤트 조건 판정", "지정한 내부 조건을 판정해 뒤의 결과 참·거짓 시 이동 명령에 결과를 제공합니다. 조건값의 세부 의미는 실행 파일 추적이 필요합니다."),
    ("본문", "이벤트 내부 참조", "선택지·분기·발견 처리 사이에서 사용하는 내부 참조값입니다. 고정 4바이트 형식은 확인됐지만 값의 세부 의미는 아직 미확인입니다."),
    ("본문", "주인공 성격 판정", "델포이 성지 이벤트에서 주인공의 성격을 판정·갱신한 뒤 보상 흐름으로 진행합니다."),
    ("본문", "이벤트 판정", "지정한 판정 종류를 실행하고 결과를 설정합니다. 뒤의 결과 참·거짓 시 이동 명령이 결과를 사용합니다."),
    ("본문", "힌트 획득", "지정한 발견물 힌트를 활성화해 이후 힌트 조건과 발견 이벤트에서 사용할 수 있게 합니다."),
    ("본문", "대화창 | 숨김·표시", "2차 숨김 또는 표시를 선택해 대화창을 잠시 감추거나 다시 표시합니다."),
    ("본문", "결과 설정 | 참·거짓", "2차 참 또는 거짓을 선택해 직전 선택·조건의 결과를 강제로 설정합니다."),
    ("본문", "행 이동 | 특수 분기", "특수 이벤트의 내부 판정 결과에 따라 지정한 행으로 이동합니다. 판정 기준은 아직 실행 파일 추적이 필요합니다."),
    ("본문", "대기", "지정한 내부 시간 단위만큼 다음 명령 실행을 멈춥니다."),
    ("본문", "날짜 경과", "고정 일수 또는 랜덤 일수 범위만큼 게임 날짜를 진행하고 시간 경과 처리를 실행합니다."),
    ("본문", "발견", "대상 발견물을 등록하고 발견 상태로 바꿉니다."),
    ("본문", "발견물 이름 설정", "이후 대사와 처리에서 사용할 대상 발견물의 표시 이름을 설정합니다."),
    ("본문", "아이템 | 획득·상실", "2차 획득 또는 상실을 선택해 지정한 아이템을 지급하거나 제거합니다."),
    ("본문", "행 이동 | 상태값 | 미만 | 대상", "3차 미만과 4차 대상 상태값을 선택합니다. 대상이 기준값보다 낮지 않으면 지정한 행으로 이동합니다."),
    ("본문", "행 이동 | 상태값 | 이하 | 대상", "3차 이하와 4차 대상 상태값을 선택합니다. 대상이 기준값 이하가 아니면 지정한 행으로 이동합니다."),
    ("본문", "소지금 | 증가·감소", "2차 증가 또는 감소를 선택해 지정한 금액만큼 소지금을 직접 변경합니다."),
    ("본문", "이벤트 플래그 설정", "지정한 전역 이벤트 플래그 ID를 활성화합니다. 플래그별 세부 의미는 아직 확인되지 않았습니다."),
    ("본문", "신도시 생성", "지정한 도시를 신도시로 생성합니다."),
    ("본문", "상태값 | 증감·설정 | 대상", "2차 증감 또는 설정과 3차 대상 상태값을 선택합니다. 수치는 고정값 또는 랜덤 범위로 입력합니다."),
    ("본문", "상태값 참조 증가", "한 상태값의 현재 수치를 다른 상태값에 더합니다. 예: 아마조네스 이벤트의 규율에 상태값 19를 더하는 형식입니다."),
    ("본문", "행 이동 | 이전 조건 | 거짓·참", "3차 거짓 또는 참을 선택합니다. 직전 예·아니오 응답 또는 명령 결과가 해당 값일 때 지정한 행으로 이동합니다."),
    ("본문", "행 이동 | 이전 판정 참", "직전에 평가한 공용 조건 값이 참일 때 지정한 행으로 이동합니다."),
    ("본문", "행 이동 | 선택지 결과", "다중 선택지 대사에서 지정한 선택값을 고르면 지정한 행으로 이동합니다."),
    ("본문", "행 이동 | 힌트 상태 | 활성·미활성 | 힌트", "3차 힌트 상태와 4차 힌트를 지정합니다. 조건이 맞지 않으면 지정한 행으로 이동합니다."),
    ("본문", "행 이동 | 아이템 상태 | 소지·미소지 | 아이템", "3차 소지 또는 미소지와 4차 아이템을 지정합니다. 아이템 상태가 조건과 맞지 않으면 지정한 행으로 이동합니다."),
    ("본문", "행 이동 | 발견물 상태 | 발견물", "3차 대상 발견물의 상태를 검사하고 조건이 맞지 않으면 지정한 행으로 이동합니다."),
    ("본문", "행 이동 | 상태값 | 이하·초과·같음 (수치) | 대상", "대상 상태값과 고정 기준값을 비교합니다. 비교가 거짓이면 지정한 행으로 이동합니다. 각각 2D(이하), 2B(초과), 2E(같음) 형식입니다."),
    ("본문", "행 이동 | 상태값 | 상태값끼리 비교 | 대상·참조", "대상 상태값과 참조 상태값을 비교합니다. 비교가 거짓이면 지정한 행으로 이동합니다."),
    ("본문", "이벤트 결과 코드", "이벤트를 종료할지, 다음 단계를 진행할지, 반복 상태로 둘지를 지정합니다."),
)

# 19/1A/22/26 1C 명령의 대상 번호.  "능력치"라는 옛 표기는 함대 상태,
# 소지금, 함선 내구도까지 함께 다루는 실제 동작을 설명하지 못하므로 상태값으로 통일한다.
STAT_COMMAND_KINDS = ("상태값 증감", "상태값 설정")
STAT_REFERENCE_COMMAND_KINDS = ("상태값 참조 증가",)
RANDOM_RANGE_COMMAND_KINDS = STAT_COMMAND_KINDS + ("날짜 경과",)
STAT_TARGETS = (
    (0, "피로도"), (1, "규율"), (2, "총 선원 수"), (3, "소지금"),
    (4, "악명"), (6, "무력"), (7, "체력"), (8, "생명력"),
    (10, "동승 인물 체력"), (11, "동승 인물 생명력"),
    # EXE의 상태값 읽기 분기(004070E6)는 출력값을 기록하지 않고 종료한다.
    (16, "상태값 16 (읽기 미지원/예약)"), (17, "명성"),
    (18, "운"), (20, "현재 함선 내구도"), (21, "지력"), (22, "매력"),
    (23, "신앙심"), (24, "동승 인물 지력"),
    # 성격값은 별자리·직업·얼굴/나이 보정으로 계산되는 8개 내부 축이다.
    # 0x31(주인공 성격 판정) 명령이 EXE 문자열을 이용해 각 축을 직접 표시한다.
    (5, "주인공 성격: 편협↔욕심쟁이"), (9, "동승 인물 성격: 소심↔거만"),
    (12, "동승 인물 사격술"), (13, "동승 인물 무력"),
    (14, "동승 인물 역사학"), (15, "주인공 아프리카토착어"),
    (19, "주인공 성격: 소심↔거만"), (25, "주인공 과학"),
    (30, "주인공 성격: 낭비가↔깍쟁이"),
    # 잉카제국 파트의 43 2E 1C 분기에서 기준값 0과 비교된다. 일반 능력치가
    # 아니라 이벤트 흐름용 상태값이지만, 원본 명령을 안전하게 편집·보존한다.
    (26, "잉카 제국 전용 판정값"),
)
STAT_TARGET_NAMES = dict(STAT_TARGETS)


def parse_hex(text: str) -> bytes:
    cleaned = "".join(text.split())
    if not cleaned:
        return b""
    if len(cleaned) % 2:
        raise ValueError("HEX 문자의 개수는 짝수여야 합니다.")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("HEX 영역에는 0~9, A~F만 입력할 수 있습니다.") from exc


def formatted_hex(data: bytes, width: int = 16) -> str:
    return "\n".join(
        " ".join(f"{value:02X}" for value in data[offset : offset + width])
        for offset in range(0, len(data), width)
    )


def encode_dialogue_text(text: str) -> bytes:
    """UI의 일반형 대사 문자를 DISEV 원본의 전각 표기로 되돌린다."""
    encoded: list[str] = []
    for char in text:
        if char == " ":
            encoded.append("\u3000")
        elif 0x21 <= ord(char) <= 0x7E:
            # 일본식 문장부호(、 「 】 등)로 치환하지 않고 게임의
            # 전각 ASCII 글꼴로 통일한다.
            encoded.append(chr(ord(char) + 0xFEE0))
        else:
            encoded.append(char)
    return "".join(encoded).encode("cp949")


def encode_multichoice_dialogue_text(text: str) -> bytes:
    """다중 선택지의 구분자는 일반 전각 슬래시가 아닌 DISEV 제어 바이트다.

    원본 선택지에는 CP949 문자 ``／``(A3 AF)가 아니라 ``81 5E``가 들어간다.
    전자는 화면에 문자 그대로 표시될 뿐이고, 후자만 게임의 선택지 분리자로
    처리된다. UI에서는 어느 쪽으로 입력해도 `/`로 받아 이 형식으로 저장한다.
    """
    choices = text.replace("／", "/").split("/")
    return b"\x81\x5E".join(encode_dialogue_text(choice) for choice in choices)


class NativeWinEdit:
    """Tk 레이아웃 안에 넣는 실제 Windows EDIT 컨트롤.

    ttk/tk Entry가 아닌 Win32 EDIT를 생성한다. 한글 IME 조합도 즉시 읽어
    검색 결과를 갱신할 수 있도록 포커스 중 텍스트를 짧은 간격으로 확인한다.
    """

    _WS_CHILD = 0x40000000
    _WS_VISIBLE = 0x10000000
    _WS_TABSTOP = 0x00010000
    _ES_AUTOHSCROLL = 0x0080
    _WS_EX_CLIENTEDGE = 0x00000200
    _SWP_NOZORDER = 0x0004
    _SWP_NOACTIVATE = 0x0010
    _WM_SETFONT = 0x0030
    _DEFAULT_GUI_FONT = 17

    def __init__(self, host: tk.Widget, on_change, width: int, height: int = 23) -> None:
        self.host = host
        self.root = host.winfo_toplevel()
        self.on_change = on_change
        self.hwnd = None
        self._user32 = None
        self._last_text = ""
        self._pending_text = ""
        self._poll_job = None
        host.configure(width=width, height=height)
        host.pack_propagate(False)
        host.grid_propagate(False)
        host.bind("<Configure>", self._resize, add="+")
        host.bind("<Map>", self._wake_poll, add="+")
        self.root.after_idle(self._create)

    def _create(self) -> None:
        if self.hwnd or not self.host.winfo_exists():
            return
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        user32.CreateWindowExW.restype = ctypes.c_void_p
        user32.GetFocus.restype = ctypes.c_void_p
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        user32.CreateWindowExW.argtypes = (
            ctypes.c_uint32, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        )
        user32.SendMessageW.argtypes = (ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)
        user32.SendMessageW.restype = ctypes.c_void_p
        user32.GetWindowTextLengthW.argtypes = (ctypes.c_void_p,)
        user32.GetWindowTextW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int)
        user32.GetWindowTextW.restype = ctypes.c_int
        user32.DestroyWindow.argtypes = (ctypes.c_void_p,)
        user32.DestroyWindow.restype = ctypes.c_bool
        user32.SetWindowPos.argtypes = (
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
            ctypes.c_int, ctypes.c_int, ctypes.c_uint,
        )
        user32.SetWindowPos.restype = ctypes.c_bool
        gdi32.GetStockObject.argtypes = (ctypes.c_int,)
        gdi32.GetStockObject.restype = ctypes.c_void_p
        self._user32 = user32
        self.hwnd = user32.CreateWindowExW(
            self._WS_EX_CLIENTEDGE, "EDIT", self._pending_text,
            self._WS_CHILD | self._WS_VISIBLE | self._WS_TABSTOP | self._ES_AUTOHSCROLL,
            0, 0, max(1, self.host.winfo_width()), max(1, self.host.winfo_height()),
            ctypes.c_void_p(self.host.winfo_id()), None, None, None,
        )
        if not self.hwnd:
            raise ctypes.WinError()
        font = gdi32.GetStockObject(self._DEFAULT_GUI_FONT)
        user32.SendMessageW(ctypes.c_void_p(self.hwnd), self._WM_SETFONT, font, ctypes.c_void_p(True))
        self._poll()

    def set_text(self, value: str) -> None:
        self._pending_text = value
        self._last_text = value
        if self.hwnd:
            ctypes.windll.user32.SetWindowTextW(ctypes.c_void_p(self.hwnd), value)

    def set_enabled(self, enabled: bool) -> None:
        if self.hwnd:
            ctypes.windll.user32.EnableWindow(ctypes.c_void_p(self.hwnd), bool(enabled))

    def _resize(self, _event=None) -> None:
        if self.hwnd:
            ctypes.windll.user32.SetWindowPos(
                ctypes.c_void_p(self.hwnd), None, 0, 0,
                max(1, self.host.winfo_width()), max(1, self.host.winfo_height()),
                self._SWP_NOZORDER | self._SWP_NOACTIVATE,
            )

    def get(self) -> str:
        if not self.hwnd or self._user32 is None:
            return ""
        length = self._user32.GetWindowTextLengthW(ctypes.c_void_p(self.hwnd))
        buffer = ctypes.create_unicode_buffer(length + 1)
        self._user32.GetWindowTextW(ctypes.c_void_p(self.hwnd), buffer, len(buffer))
        return buffer.value

    def _poll(self) -> None:
        try:
            if not self.hwnd or not self.host.winfo_exists():
                return
            focused = self.host.winfo_ismapped() and self._user32.GetFocus() == self.hwnd
            if focused:
                value = self.get()
                if value != self._last_text:
                    self._last_text = value
                    self.on_change()
            self._poll_job = self.root.after(50 if focused else 250, self._poll)
        except tk.TclError:
            self._poll_job = None

    def _wake_poll(self, _event=None) -> None:
        if self._poll_job is not None:
            try:
                self.root.after_cancel(self._poll_job)
            except tk.TclError:
                pass
        self._poll_job = self.root.after_idle(self._poll)

    def destroy(self) -> None:
        if self._poll_job is not None:
            self.root.after_cancel(self._poll_job)
            self._poll_job = None
        if self.hwnd and self._user32 is not None:
            self._user32.DestroyWindow(ctypes.c_void_p(self.hwnd))
            self.hwnd = None


class NativeEdit:
    """StringVar와 Tk grid 배치를 지원하는 Win32 EDIT 어댑터."""

    def __init__(
        self,
        parent: tk.Widget,
        textvariable: tk.StringVar,
        width: int = 160,
        *,
        numeric: bool = False,
        allow_negative: bool = False,
    ) -> None:
        self.variable = textvariable
        self._numeric = numeric
        self._allow_negative = allow_negative
        self.host = tk.Frame(parent, width=width, height=23)
        self._state = "normal"
        self._updating = False
        self.native = NativeWinEdit(self.host, self._native_changed, width=width, height=23)
        self._trace_id = self.variable.trace_add("write", self._variable_changed)
        self.host.bind("<Destroy>", self._destroy, add="+")
        self.native.set_text(self.variable.get())

    @property
    def master(self) -> tk.Widget:
        return self.host.master

    def _native_changed(self) -> None:
        if not self._updating:
            value = self.native.get()
            if self._numeric:
                value = self._numeric_text(value)
                if value != self.native.get():
                    self.native.set_text(value)
            self._updating = True
            self.variable.set(value)
            self._updating = False

    def _numeric_text(self, value: str) -> str:
        """숫자 입력칸은 숫자와 필요한 선행 음수 부호만 통과시킨다."""
        digits = "".join(character for character in value if character.isascii() and character.isdigit())
        return ("-" if self._allow_negative and value.startswith("-") else "") + digits

    def _variable_changed(self, *_args) -> None:
        if not self._updating:
            self.native.set_text(self.variable.get())

    def _destroy(self, _event=None) -> None:
        try:
            self.variable.trace_remove("write", self._trace_id)
        except tk.TclError:
            pass
        self.native.destroy()

    def grid(self, *args, **kwargs) -> None:
        self.host.grid(*args, **kwargs)

    def grid_remove(self) -> None:
        self.host.grid_remove()

    def grid_info(self):
        return self.host.grid_info()

    def configure(self, **kwargs) -> None:
        state = kwargs.pop("state", None)
        if state is not None:
            self._state = state
            self.native.set_enabled(state != "disabled")
        if kwargs:
            self.host.configure(**kwargs)

    config = configure

    def cget(self, key: str):
        return self._state if key == "state" else self.host.cget(key)


def rebuild_archive(
    original: bytes,
    entries: list[disev.ArchiveEntry],
    decoded_parts: list[bytes],
    modified: set[int],
) -> bytes:
    if len(entries) != len(decoded_parts):
        raise ValueError("파트 테이블과 편집 데이터의 개수가 다릅니다.")

    blobs: list[bytes] = []
    metadata: list[tuple[int, int]] = []
    for index, (entry, decoded) in enumerate(zip(entries, decoded_parts)):
        if index in modified:
            blobs.append(decoded)
            metadata.append((len(decoded), len(decoded)))
        else:
            blob = original[
                entry.payload_offset : entry.payload_offset + entry.compressed
            ]
            blobs.append(blob)
            metadata.append((entry.compressed, entry.uncompressed))

    table_end = 0x110 + len(entries) * 12 + 4
    output = bytearray(original[:0x110])
    payload_offset = table_end
    for (compressed, uncompressed), blob in zip(metadata, blobs):
        output.extend(struct.pack(">III", compressed, uncompressed, payload_offset))
        payload_offset += compressed
    output.extend(b"\0\0\0\0")
    output.extend(b"".join(blobs))
    return bytes(output)


def verify_archive(data: bytes, expected_parts: list[bytes]) -> None:
    entries = disev.parse_archive(data)
    if len(entries) != len(expected_parts):
        raise ValueError("저장 검증 중 파트 개수가 변경되었습니다.")
    dictionary = data[0x10:0x110]
    for index, (entry, expected) in enumerate(zip(entries, expected_parts)):
        actual = disev.decode_part(data, entry, dictionary)
        if actual != expected:
            raise ValueError(f"저장 검증 실패: 파트 {index}의 내용이 일치하지 않습니다.")
        disev.validate_part(actual, index)


class DisevEditor:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        try:
            self.root.iconbitmap(default=str(_resource_data_dir().parent / "Icon.ico"))
        except tk.TclError:
            # 아이콘 리소스가 없는 개발·진단 환경에서도 편집기는 실행한다.
            pass
        self.root.geometry("1180x760")
        self.root.minsize(980, 650)

        self.disev_path: Path | None = None
        self.exe_path: Path | None = None
        self.archive = b""
        self.entries: list[disev.ArchiveEntry] = []
        self.parts: list[bytes] = []
        self.original_parts: list[bytes] = []
        self.rows: list[disev.DiscoveryRow] = []
        self.discovery_part_map: dict[int, int] = {}
        self.modified: set[int] = set()
        self.current_index: int | None = None
        self.current_discovery_id: int | None = None
        self.loading_editor = False
        self.pending = False
        self._update_check_in_progress = False
        self._update_download_in_progress = False
        self._update_notice = self._consume_update_notice()
        self.filter_after: str | None = None
        self.discovery_column_fit_after: str | None = None
        self.condition_kind_var = tk.StringVar(value="항상 실행")
        self.condition_subkind_var = tk.StringVar()
        self.condition_value_vars = (tk.StringVar(value="0"), tk.StringVar(value="0"))
        self.condition_value_labels: list[ttk.Label] = []
        self.condition_value_spins: list[ttk.Spinbox] = []
        self.condition_target_var = tk.StringVar()
        self.character_targets: list[tuple[int, str]] = self._load_condition_targets("character_database.json")
        self.sponsor_targets: list[tuple[int, str]] = self._load_condition_targets("sponsor_data.json")
        self.discovery_targets: list[tuple[int, str]] = []
        self.item_targets: list[tuple[int, str]] = self._load_item_targets()
        self.city_targets: list[tuple[int, str]] = self._load_city_targets()
        self.nation_targets: list[tuple[int, str]] = self._load_nation_targets()
        self.building_targets: list[tuple[int, str]] = self._load_building_targets()
        self.culture_targets: list[tuple[int, str]] = self._load_culture_targets()
        self.condition_tokens: list[tuple[str, tuple[int, ...]]] | None = []
        self.selected_condition_index: int | None = None
        self.body_tokens: list[dict[str, object]] = []
        self.selected_body_index: int | None = None
        self.body_command_var = tk.StringVar(value="-")
        self.body_subkind_var = tk.StringVar()
        self.body_detail_var = tk.StringVar()
        self.body_value_var = tk.StringVar()
        self.body_value2_var = tk.StringVar()
        self.body_range_end_var = tk.StringVar()
        self.special_check_value_var = tk.StringVar()
        self.special_difficulty_var = tk.StringVar()
        self.body_random_var = tk.BooleanVar(value=False)
        self.body_speaker_var = tk.StringVar(value="화자 없음")
        self.body_character_var = tk.StringVar()
        self.body_item_var = tk.StringVar()
        self.body_city_var = tk.StringVar()
        self.body_stat_target_var = tk.StringVar()
        self.body_hint_state_var = tk.StringVar(value="활성")
        self.body_hint_var = tk.StringVar()
        self.body_result_var = tk.StringVar(value=EVENT_RESULT_NAMES[0])
        self.hint_targets = self._load_hint_targets()
        self.theme_names = tuple(ttk.Style(self.root).theme_names())
        default_theme = self.theme_names[0] if self.theme_names else "clam"
        self.theme_var = tk.StringVar(
            value=_load_saved_theme("disev_editor_theme", self.theme_names) or default_theme
        )
        self.dialogue_speakers = {
            "화자 없음": b"",
            **{
                name: tag + b"\x81\x46"
                for tag, name in disev.SPEAKER_NAMES.items()
            },
        }

        self._configure_styles()
        self._build_ui()
        for combo in (
            self.condition_kind_combo,
            self.condition_subkind_combo,
            self.condition_target_combo,
            self.body_kind_combo,
            self.body_subkind_combo,
            self.body_detail_combo,
            self.body_fourth_combo,
            self.body_speaker_combo,
            self.body_character_combo,
            self.body_item_combo,
            self.body_city_combo,
            self.body_stat_target_combo,
            self.body_hint_state_combo,
            self.body_hint_combo,
            self.body_result_combo,
            self.guide_filter_combo,
        ):
            combo.bind("<Up>", self._cycle_combobox)
            combo.bind("<Down>", self._cycle_combobox)
        self.root.after_idle(self._autosize_all_comboboxes)
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        # 위젯의 최소 크기 계산이 끝난 뒤 중앙화해야 초기 배치가 밀리지 않는다.
        self.root.after(100, self._finish_startup)
        if self._update_notice is not None:
            self.root.after(400, self._show_update_notice)
        if UPDATE_LATEST_URL:
            self.root.after(1500, lambda: self.check_for_updates(automatic=True))

    def _autosize_combobox(self, combo: ttk.Combobox, minimum: int = 6, maximum: int | None = None) -> None:
        """목록의 가장 긴 텍스트에 맞춰 네이티브 콤보 상자의 문자 폭을 맞춘다."""
        try:
            if maximum is not None:
                combo._auto_width_maximum = maximum
            maximum = getattr(combo, "_auto_width_maximum", None)
            # Tcl은 -values를 공백이 들어간 단일 문자열로 돌려줄 수 있다.
            # 파이썬 문자열을 바로 순회하면 항목이 아니라 글자별 길이만 계산된다.
            values = tuple(str(value) for value in combo.tk.splitlist(combo.cget("values")))
            candidates = values + ((str(combo.get()),) if combo.get() else ())
            if not candidates:
                combo.configure(width=minimum)
                return
            font_name = combo.cget("font")
            try:
                font = tkfont.nametofont(font_name) if font_name else tkfont.nametofont("TkTextFont")
            except tk.TclError:
                # 일부 ttk 테마는 TkTextFont 이름을 등록하지 않는다. 이 경우
                # 편집기 공통 글꼴과 같은 크기의 측정용 폰트를 만든다.
                font = tkfont.Font(root=combo, family="맑은 고딕", size=9)
            zero_width = max(1, font.measure("0"))
            widest = max(font.measure(value) for value in candidates)
            # 드롭다운 화살표와 좌우 여백을 위해 3문자를 더한다.
            width = max(minimum, (widest + zero_width - 1) // zero_width + 3)
            combo.configure(width=min(width, maximum) if maximum is not None else width)
        except tk.TclError:
            # 초기 테마 적용 중에는 일부 폰트가 아직 준비되지 않을 수 있다.
            pass

    def _autosize_all_comboboxes(self) -> None:
        def visit(widget: tk.Misc) -> None:
            if isinstance(widget, ttk.Combobox):
                self._autosize_combobox(widget)
            for child in widget.winfo_children():
                visit(child)

        visit(self.root)

    def _tree_font(self, style_name: str) -> tkfont.Font:
        """테마별 Treeview 글꼴을 얻고, 없으면 기본 글꼴을 사용한다."""
        font_name = ttk.Style(self.root).lookup(style_name, "font") or "TkDefaultFont"
        try:
            return tkfont.nametofont(font_name)
        except tk.TclError:
            return tkfont.nametofont("TkDefaultFont")

    def _autosize_tree_columns(self, tree: ttk.Treeview, skip: tuple[str, ...] = ()) -> None:
        """마지막 값 열처럼 늘어나는 열을 제외하고 내용·제목 폭에 맞춘다."""
        columns = tuple(str(column) for column in tree.cget("columns"))
        value_font = self._tree_font("Treeview")
        heading_font = self._tree_font("Treeview.Heading")
        for index, column in enumerate(columns):
            if column in skip:
                continue
            widest = heading_font.measure(str(tree.heading(column, "text")))
            for item in tree.get_children(""):
                values = tree.item(item, "values")
                if index < len(values):
                    widest = max(widest, value_font.measure(str(values[index])))
            tree.column(column, width=max(36, widest + 22), stretch=False)

    def _autosize_discovery_tree_and_panel(self) -> None:
        """두 발견물 열의 내용 폭을 고정하고, 그 합계에 맞춰 왼쪽 패널을 조정한다."""
        if not self.tree.winfo_exists():
            return
        self._autosize_tree_columns(self.tree)
        # 우선 내용 폭으로 왼쪽 패널의 기준 폭을 정한다. 실제 배치 폭은 아래의
        # _fit_discovery_columns_to_tree_width()에서 한 번 더 맞춘다.
        for column in self.tree.cget("columns"):
            width = int(self.tree.column(column, "width"))
            self.tree.column(column, width=width, minwidth=width, stretch=False)
        required = sum(int(self.tree.column(column, "width")) for column in self.tree.cget("columns"))
        # 좌우 프레임 padding·세로 스크롤바·Treeview 테두리까지 포함한다.
        required += 38
        available = max(240, self.root.winfo_width() - 480)
        try:
            self.main_pane.sashpos(0, min(max(180, required), available))
        except tk.TclError:
            pass
        self._schedule_discovery_column_fit()

    def _schedule_discovery_column_fit(self, _event=None) -> None:
        """배치가 완료된 실제 목록 폭에 맞춰 두 열의 합계를 보정한다."""
        if self.discovery_column_fit_after is not None:
            try:
                self.root.after_cancel(self.discovery_column_fit_after)
            except tk.TclError:
                pass
        self.discovery_column_fit_after = self.root.after_idle(self._fit_discovery_columns_to_tree_width)

    def _fit_discovery_columns_to_tree_width(self) -> None:
        self.discovery_column_fit_after = None
        if not self.tree.winfo_exists() or self.tree.winfo_width() <= 1:
            return
        columns = tuple(self.tree.cget("columns"))
        if columns != ("discovery_id", "name"):
            return
        # Treeview의 실제 폭은 외부 스크롤바를 제외한 목록 영역이다.
        available = max(1, self.tree.winfo_width() - 2)
        id_width = int(self.tree.column("discovery_id", "width"))
        name_width = int(self.tree.column("name", "width"))
        difference = available - (id_width + name_width)
        if difference:
            # ID 열은 내용 폭을 기준으로 유지하고, 발견물 열이 남거나 부족한 폭을
            # 받아 두 열의 합계가 실제 목록 폭과 일치하게 한다.
            name_width = max(36, name_width + difference)
            self.tree.column("name", width=name_width, minwidth=name_width, stretch=False)
        for column in columns:
            width = int(self.tree.column(column, "width"))
            self.tree.column(column, width=width, minwidth=width, stretch=False)

    def _block_discovery_column_resize(self, event: tk.Event) -> str | None:
        """발견물 목록의 열 경계 드래그를 차단해 자동 계산한 폭을 보존한다."""
        if self.tree.identify_region(event.x, event.y) == "separator":
            return "break"
        return None

    def _configure_styles(self, theme_name: str | None = None) -> None:
        style = ttk.Style(self.root)
        requested = theme_name or self.theme_var.get()
        if requested not in style.theme_names():
            requested = self.theme_names[0] if self.theme_names else "clam"
        try:
            style.theme_use(requested)
        except tk.TclError:
            requested = self.theme_names[0] if self.theme_names else "clam"
            style.theme_use(requested)
        self.theme_var.set(requested)
        # 색상은 고정하지 않고 선택한 Tk 테마의 기본 팔레트를 그대로 따른다.
        style.configure(".", font=("Malgun Gothic", 9))
        style.configure("TNotebook.Tab", padding=[10, 4], font=("Malgun Gothic", 9))
        style.configure("Treeview", rowheight=22, font=("Malgun Gothic", 9))
        style.configure("Treeview.Heading", font=("Malgun Gothic", 9, "bold"))

    def _change_theme(self, _event: tk.Event | None = None) -> None:
        self._configure_styles(self.theme_var.get())
        self.root.after_idle(self._autosize_all_comboboxes)
        _save_theme("disev_editor_theme", self.theme_var.get())

    @staticmethod
    def _cycle_combobox(event: tk.Event) -> str | None:
        """화살표 키로 펼치지 않고 인접한 콤보 항목을 선택한다."""
        combo = event.widget
        if str(combo.cget("state")) == "disabled":
            return "break"
        values = combo.cget("values")
        if not values:
            return "break"
        current = combo.current()
        direction = -1 if event.keysym == "Up" else 1
        if current < 0:
            next_index = len(values) - 1 if direction < 0 else 0
        else:
            next_index = max(0, min(len(values) - 1, current + direction))
        if next_index != current:
            combo.current(next_index)
            combo.event_generate("<<ComboboxSelected>>")
        return "break"

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self.root, padding=(8, 7, 8, 5))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text=ui("open_disev"), command=self._open_disev).pack(side="left")
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(toolbar, text=ui("save"), command=self._save).pack(side="left")
        self.update_button = ttk.Button(toolbar, text=ui("check_updates"), command=self.check_for_updates)
        self.theme_combo = ttk.Combobox(
            toolbar, textvariable=self.theme_var, values=self.theme_names,
            state="readonly", width=11,
        )
        self.theme_combo.pack(side="right")
        self.theme_combo.bind("<<ComboboxSelected>>", self._change_theme)
        ttk.Label(toolbar, text=ui("theme")).pack(side="right", padx=(0, 4))
        ttk.Label(toolbar, text=ui("fixed_length_mode")).pack(side="right")

        pane = ttk.Panedwindow(self.root, orient="horizontal")
        self.main_pane = pane
        pane.pack(fill="both", expand=True, padx=8, pady=(0, 5))

        left = ttk.Frame(pane, padding=5)
        right = ttk.Frame(pane, padding=5)
        pane.add(left, weight=3)
        pane.add(right, weight=5)

        search_row = ttk.Frame(left)
        search_row.pack(fill="x", pady=(0, 5))
        ttk.Label(search_row, text=ui("search")).pack(side="left")
        search_host = tk.Frame(search_row, width=95, height=23)
        search_host.pack(side="left", padx=(5, 0))
        search_host.pack_propagate(False)
        self.search_edit = NativeWinEdit(search_host, self._schedule_filter, width=95, height=23)

        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill="both", expand=True)
        columns = ("discovery_id", "name")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "discovery_id": "ID",
            "name": ui("discovery"),
        }
        widths = {"discovery_id": 52, "name": 150}
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="center", stretch=False)
        self.tree_scrollbar = tk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self._update_tree_scrollbar)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.tree.grid(row=0, column=0, sticky="nsew")
        # 처음에는 배치한 뒤, 실제 행 수가 한 화면에 들어갈 때만 grid_remove한다.
        self.tree_scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<Configure>", self._schedule_tree_scrollbar_sync, add="+")
        self.tree.bind("<Configure>", self._schedule_discovery_column_fit, add="+")
        self.tree.bind("<ButtonPress-1>", self._block_discovery_column_resize, add="+")
        self.tree.bind("<<TreeviewSelect>>", self._select_part)
        self._enable_tree_zebra(self.tree)

        right_tabs = ttk.Notebook(right)
        right_tabs.pack(fill="both", expand=True)
        edit_tab = ttk.Frame(right_tabs, padding=8)
        guide_tab = ttk.Frame(right_tabs, padding=8)
        right_tabs.add(edit_tab, text=ui("edit_tab"))
        right_tabs.add(guide_tab, text=ui("guide_tab"))

        chunks = ttk.Panedwindow(edit_tab, orient="vertical")
        chunks.pack(fill="both", expand=True, pady=(0, 7))
        condition_frame = ttk.LabelFrame(chunks, text=ui("condition"), padding=6)
        body_frame = ttk.LabelFrame(chunks, text=ui("command"), padding=6)
        # 조건은 편집 줄과 목록 3행만 필요하므로 남는 높이는 본문에 배분한다.
        chunks.add(condition_frame, weight=0)
        chunks.add(body_frame, weight=1)

        condition_builder = ttk.Frame(condition_frame)
        condition_builder.pack(fill="x", padx=2, pady=(2, 6))
        ttk.Label(condition_builder, text=ui("first_level")).grid(row=0, column=0, sticky="e")
        self.condition_kind_combo = ttk.Combobox(
            condition_builder,
            textvariable=self.condition_kind_var,
            values=tuple(CONDITION_GROUPS),
            state="readonly",
            width=13,
        )
        self.condition_kind_combo.grid(row=0, column=1, sticky="w", padx=(5, 10))
        self.condition_kind_combo.bind("<<ComboboxSelected>>", self._condition_kind_changed)
        self.condition_subkind_label = ttk.Label(condition_builder, text=ui("second_level"))
        self.condition_subkind_combo = ttk.Combobox(
            condition_builder, textvariable=self.condition_subkind_var,
            state="readonly", width=11,
        )
        self.condition_subkind_combo.bind("<<ComboboxSelected>>", self._condition_kind_changed)
        for value_index in range(2):
            label = ttk.Label(condition_builder, text="")
            spin = ttk.Spinbox(
                condition_builder,
                from_=0,
                to=65535,
                textvariable=self.condition_value_vars[value_index],
                width=8,
            )
            self.condition_value_labels.append(label)
            self.condition_value_spins.append(spin)
        self.condition_target_label = ttk.Label(condition_builder, text=ui("target"))
        self.condition_target_combo = ttk.Combobox(
            condition_builder,
            textvariable=self.condition_target_var,
            state="readonly",
            width=31,
        )
        self.condition_summary_var = tk.StringVar(value=ui("always_execute"))
        action_row = ttk.Frame(condition_builder)
        action_row.grid(row=1, column=0, columnspan=10, sticky="w", pady=(7, 0))
        self.condition_edit_button = ttk.Button(action_row, text=ui("edit"), command=self._apply_condition_token)
        self.condition_edit_button.pack(side="left")
        self.condition_add_button = ttk.Button(action_row, text=ui("add"), command=self._add_condition_token)
        self.condition_add_button.pack(side="left", padx=(6, 0))
        self.condition_insert_button = ttk.Button(action_row, text=ui("insert"), command=self._insert_condition_token)
        self.condition_insert_button.pack(side="left", padx=(6, 0))
        self.condition_remove_button = ttk.Button(action_row, text=ui("remove"), command=self._remove_selected_condition)
        self.condition_remove_button.pack(side="left", padx=(6, 0))
        self.condition_clear_button = ttk.Button(action_row, text=ui("clear_all"), command=self._clear_conditions)
        self.condition_clear_button.pack(side="left", padx=(6, 0))
        condition_builder.columnconfigure(7, weight=1)
        self._condition_kind_changed()

        condition_list_host = ttk.Frame(condition_frame)
        condition_list_host.pack(fill="x")
        self.condition_tree = self._make_condition_list(condition_list_host)
        self.body_tree = self._make_body_list(body_frame)

        buttons = ttk.Frame(edit_tab)
        buttons.pack(fill="x")
        ttk.Label(
            buttons,
            text=ui("resize_notice"),
        ).pack(side="left")
        ttk.Button(buttons, text=ui("apply_changes"), command=self._apply_editor).pack(side="right")
        ttk.Button(buttons, text=ui("revert_part"), command=self._revert_part).pack(side="right", padx=(0, 6))

        self._make_command_guide(guide_tab)

        status_frame = ttk.Frame(self.root, padding=(8, 2, 8, 6))
        status_frame.pack(fill="x")
        self.status_var = tk.StringVar(value=ui("ready"))
        ttk.Label(status_frame, textvariable=self.status_var).pack(side="left")
        self.dirty_var = tk.StringVar()
        ttk.Label(status_frame, textvariable=self.dirty_var).pack(side="right")

        self._set_edit_state(False)

    def _make_command_guide(self, parent: ttk.Frame) -> None:
        """조건·본문 명령의 실행 의미를 별도 목록으로 보여 준다."""
        filter_row = ttk.Frame(parent)
        filter_row.pack(fill="x", pady=(0, 6))
        ttk.Label(filter_row, text=ui("category")).pack(side="left")
        self.guide_filter_var = tk.StringVar(value=ui("all"))
        self.guide_filter_combo = ttk.Combobox(
            filter_row, textvariable=self.guide_filter_var,
            values=(ui("all"), ui("condition"), ui("body")), state="readonly", width=10,
        )
        self.guide_filter_combo.pack(side="left", padx=(5, 0))
        self.guide_filter_combo.bind("<<ComboboxSelected>>", self._refresh_command_guide)
        host = ttk.Frame(parent)
        host.pack(fill="both", expand=True)
        self.command_guide_tree = ttk.Treeview(host, columns=("area", "command", "description"), show="headings")
        self.command_guide_tree.heading("area", text=ui("guide_area"))
        self.command_guide_tree.heading("command", text=ui("guide_command"))
        self.command_guide_tree.heading("description", text=ui("guide_description"))
        self.command_guide_tree.column("area", width=72, anchor="center", stretch=False)
        self.command_guide_tree.column("command", width=190, anchor="w", stretch=False)
        self.command_guide_tree.column("description", width=560, anchor="w", stretch=True)
        scrollbar = ttk.Scrollbar(host, orient="vertical", command=self.command_guide_tree.yview)
        self.command_guide_tree.configure(yscrollcommand=scrollbar.set)
        self.command_guide_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self._enable_tree_zebra(self.command_guide_tree)
        self._refresh_command_guide()

    def _refresh_command_guide(self, _event=None) -> None:
        """선택한 구분에 맞게 명령 안내 목록을 다시 채운다."""
        selected = self.guide_filter_var.get()
        tree = self.command_guide_tree
        tree.delete(*tree.get_children())
        for index, row in enumerate(COMMAND_GUIDE):
            if selected != "전체" and row[0] != selected:
                continue
            tree.insert("", "end", iid=f"guide-{index}", values=row)

    @staticmethod
    def _enable_tree_zebra(tree: ttk.Treeview) -> None:
        """세이브 에디터와 동일하게 목록 행을 흰색/연회색으로 교차 표시한다."""
        tree.tag_configure("zebra_odd", background="#FFFFFF")
        tree.tag_configure("zebra_even", background="#F0F0F0")
        original_insert = tree.insert
        original_delete = tree.delete
        tree._zebra_next_index = 0

        def striped_insert(*args, **kwargs):
            custom_tags = tuple(kwargs.pop("tags", ()))
            zebra = "zebra_odd" if tree._zebra_next_index % 2 == 0 else "zebra_even"
            kwargs["tags"] = (zebra, *custom_tags)
            item = original_insert(*args, **kwargs)
            tree._zebra_next_index += 1
            return item

        def striped_delete(*items):
            result = original_delete(*items)
            if not tree.get_children(""):
                tree._zebra_next_index = 0
            return result

        tree.insert = striped_insert
        tree.delete = striped_delete

    def _make_condition_list(self, parent: ttk.Frame) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.grid(row=0, column=0, sticky="nsew")
        parent.rowconfigure(0, weight=0)
        parent.columnconfigure(0, weight=1)
        tree = ttk.Treeview(
            frame,
            columns=("number", "primary", "secondary", "value1", "value2", "remark"),
            show="headings",
            selectmode="browse",
            height=3,
        )
        tree.heading("number", text="No.")
        tree.heading("primary", text="1차")
        tree.heading("secondary", text="2차")
        tree.heading("value1", text="값 1")
        tree.heading("value2", text="값 2")
        tree.heading("remark", text="비고")
        tree.column("number", width=48, anchor="center", stretch=False)
        tree.column("primary", width=110, anchor="w", stretch=False)
        tree.column("secondary", width=100, anchor="w", stretch=False)
        tree.column("value1", width=95, anchor="w", stretch=False)
        tree.column("value2", width=95, anchor="w", stretch=False)
        tree.column("remark", width=210, anchor="w", stretch=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="x", expand=True)
        scrollbar.pack(side="right", fill="y")
        tree.bind("<<TreeviewSelect>>", self._select_condition)
        self._enable_tree_zebra(tree)
        return tree

    def _make_body_list(self, parent: ttk.Frame) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        editor = ttk.Frame(frame)
        editor.pack(fill="x", pady=(0, 6))
        # 분류 행은 입력 행과 분리한다. 아래의 가변 입력폭이 분류 콤보 간격에 영향을 주지 않는다.
        classification_row = ttk.Frame(editor)
        classification_row.grid(row=0, column=0, columnspan=11, sticky="w")
        self.body_input_row = ttk.Frame(editor)
        self.body_input_row.grid(row=1, column=0, columnspan=11, sticky="ew", pady=(4, 0))
        self.body_input_row.columnconfigure(1, weight=1)
        self.body_input_row.columnconfigure(3, weight=1)
        self.body_input_row.columnconfigure(5, weight=1)
        ttk.Label(classification_row, text="1차:").grid(row=0, column=0, sticky="w")
        self.body_kind_combo = ttk.Combobox(classification_row, textvariable=self.body_command_var, values=tuple(BODY_COMMAND_GROUPS), state="readonly", width=22)
        self.body_kind_combo.grid(row=0, column=1, sticky="w", padx=(5, 10))
        self.body_kind_combo.bind("<<ComboboxSelected>>", self._body_kind_changed)
        self.body_subkind_label = ttk.Label(classification_row, text="2차:")
        self.body_subkind_combo = ttk.Combobox(classification_row, textvariable=self.body_subkind_var, state="readonly", width=14)
        self.body_subkind_combo.bind("<<ComboboxSelected>>", self._body_kind_changed)
        self.body_detail_label = ttk.Label(classification_row, text="3차:")
        self.body_detail_combo = ttk.Combobox(classification_row, textvariable=self.body_detail_var, state="readonly", width=14)
        self.body_detail_combo.bind("<<ComboboxSelected>>", self._body_kind_changed)
        self.body_fourth_label = ttk.Label(classification_row, text="4차:")
        self.body_fourth_combo = ttk.Combobox(classification_row, textvariable=self.body_hint_var, state="readonly", width=22)
        self.body_fourth_combo.bind("<<ComboboxSelected>>", self._body_kind_changed)
        self.body_value_label = ttk.Label(editor, text="값:")
        self.body_value_label.grid(row=0, column=2, sticky="e")
        self.body_value_entry = NativeEdit(editor, self.body_value_var, width=220)
        self.body_value_entry.grid(row=0, column=3, sticky="ew", padx=(5, 0))
        self.body_value2_label = ttk.Checkbutton(
            editor, text="랜덤 범위:", variable=self.body_random_var, command=self._body_random_changed,
        )
        self.body_value2_plain_label = ttk.Label(editor, text="기준값:")
        self.body_value2_entry = NativeEdit(editor, self.body_value2_var, width=130)
        self.special_check_value_label = ttk.Label(editor, text="판정값:")
        self.special_check_value_entry = NativeEdit(editor, self.special_check_value_var, width=150)
        self.special_difficulty_label = ttk.Label(editor, text="난이도:")
        self.special_difficulty_entry = NativeEdit(editor, self.special_difficulty_var, width=150)
        self.body_speaker_label = ttk.Label(classification_row, text="화자:")
        self.body_speaker_combo = ttk.Combobox(
            classification_row,
            textvariable=self.body_speaker_var,
            values=tuple(self.dialogue_speakers),
            state="readonly",
            width=22,
        )
        self.body_speaker_label.grid(row=0, column=4, sticky="w")
        self.body_speaker_combo.grid(row=0, column=5, sticky="w", padx=(5, 10))
        self.body_character_label = ttk.Label(editor, text="대상 발견물:")
        self.body_character_combo = ttk.Combobox(
            editor,
            textvariable=self.body_character_var,
            values=(),
            state="readonly",
            width=22,
        )
        # 발견물 이름 설정의 대상은 명령 바이트에 이미 기록되어 있다.
        # 선택 UI가 아니라, 해당 대상을 보여 주는 읽기 전용 텍스트로 표시한다.
        self.body_character_entry = NativeEdit(editor, self.body_character_var, width=180)
        self.body_character_entry.configure(state="disabled")
        self.body_character_label.grid(row=0, column=4, sticky="e", padx=(10, 0))
        self.body_character_combo.grid(row=0, column=5, sticky="w", padx=(5, 0))
        self.body_item_combo = ttk.Combobox(
            editor,
            textvariable=self.body_item_var,
            values=tuple(name for _item_id, name in self.item_targets),
            state="readonly",
            width=28,
        )
        self.body_item_combo.grid(row=0, column=3, sticky="ew", padx=(5, 0))
        self.body_city_combo = ttk.Combobox(
            editor,
            textvariable=self.body_city_var,
            values=tuple(name for _city_id, name in self.city_targets),
            state="readonly",
            width=28,
        )
        self.body_city_combo.grid(row=0, column=3, sticky="ew", padx=(5, 0))
        self.body_result_combo = ttk.Combobox(
            editor,
            textvariable=self.body_result_var,
            values=tuple(name for _code, name in EVENT_RESULT_CODES),
            state="readonly",
            width=18,
        )
        self.body_result_combo.grid(row=0, column=3, sticky="ew", padx=(5, 0))
        self.body_stat_target_label = ttk.Label(editor, text="대상:")
        self.body_stat_target_combo = ttk.Combobox(
            editor,
            textvariable=self.body_stat_target_var,
            values=tuple(name for _target_id, name in STAT_TARGETS),
            state="readonly",
            width=14,
        )
        self.body_stat_target_label.grid(row=0, column=4, sticky="e", padx=(10, 0))
        self.body_stat_target_combo.grid(row=0, column=5, sticky="w", padx=(5, 0))
        self.body_hint_state_label = ttk.Label(editor, text="힌트 상태:")
        self.body_hint_state_combo = ttk.Combobox(
            editor, textvariable=self.body_hint_state_var, values=("활성", "미활성"), state="readonly", width=8,
        )
        self.body_hint_label = ttk.Label(editor, text="힌트:")
        self.body_hint_combo = ttk.Combobox(
            editor, textvariable=self.body_hint_var,
            values=tuple(name for _hint_id, name in self.hint_targets), state="readonly", width=14,
        )
        self.body_action_row = ttk.Frame(editor)
        self.body_action_row.grid(row=2, column=0, columnspan=11, sticky="w", pady=(6, 0))
        self.body_edit_button = ttk.Button(self.body_action_row, text="수정", command=self._apply_body_command)
        self.body_edit_button.pack(side="left")
        self.body_add_button = ttk.Button(self.body_action_row, text="추가", command=self._add_body_command)
        self.body_add_button.pack(side="left", padx=(6, 0))
        self.body_insert_button = ttk.Button(self.body_action_row, text="삽입", command=self._insert_body_command)
        self.body_insert_button.pack(side="left", padx=(6, 0))
        self.body_remove_button = ttk.Button(self.body_action_row, text="제거", command=self._remove_body_command)
        self.body_remove_button.pack(side="left", padx=(6, 0))
        # 상태값 명령에서는 _body_kind_changed가 수치 입력 열에만 남는 폭을 준다.
        editor.columnconfigure(3, weight=0)
        editor.columnconfigure(5, weight=0)
        editor.columnconfigure(7, weight=0)
        self.body_speaker_label.grid_remove()
        self.body_speaker_combo.grid_remove()
        self.body_fourth_label.grid_remove()
        self.body_fourth_combo.grid_remove()
        self.body_character_label.grid_remove()
        self.body_character_combo.grid_remove()
        self.body_character_entry.grid_remove()
        self.body_item_combo.grid_remove()
        self.body_city_combo.grid_remove()
        self.body_result_combo.grid_remove()
        self.body_stat_target_label.grid_remove()
        self.body_stat_target_combo.grid_remove()
        self.body_hint_state_label.grid_remove()
        self.body_hint_state_combo.grid_remove()
        self.body_hint_label.grid_remove()
        self.body_hint_combo.grid_remove()
        self.body_value_label.grid_remove()
        self.body_value_entry.grid_remove()
        self.body_value2_label.grid_remove()
        self.body_value2_plain_label.grid_remove()
        self.body_value2_entry.grid_remove()
        self.special_check_value_label.grid_remove()
        self.special_check_value_entry.grid_remove()
        self.special_difficulty_label.grid_remove()
        self.special_difficulty_entry.grid_remove()
        self.body_value_entry.configure(state="disabled")
        self.body_value2_entry.configure(state="disabled")
        self.body_edit_button.configure(state="disabled")

        list_frame = ttk.Frame(frame)
        list_frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(list_frame, columns=("number", "class1", "class2", "class3", "class4", "value"), show="headings", selectmode="browse")
        tree.heading("number", text="No.")
        tree.heading("class1", text="1차")
        tree.heading("class2", text="2차")
        tree.heading("class3", text="3차")
        tree.heading("class4", text="4차")
        tree.heading("value", text="값")
        tree.column("number", width=48, anchor="center", stretch=False)
        tree.column("class1", width=110, anchor="w", stretch=False)
        tree.column("class2", width=110, anchor="w", stretch=False)
        tree.column("class3", width=120, anchor="w", stretch=False)
        tree.column("class4", width=140, anchor="w", stretch=False)
        tree.column("value", width=300, anchor="w", stretch=True)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        tree.bind("<<TreeviewSelect>>", self._select_body_command)
        self._enable_tree_zebra(tree)
        return tree

    def _update_tree_scrollbar(self, first: str, last: str) -> None:
        """Treeview의 스크롤 thumb 위치만 동기화한다.

        표시 여부는 렌더링 직후의 행 수/높이로 판정한다. Windows Tk에서는
        내용 교체 직후 yscrollcommand가 0.0, 1.0을 먼저 보내는 경우가 있다.
        """
        self.tree_scrollbar.set(first, last)

    def _sync_tree_scrollbar(self) -> None:
        """검색 결과가 실제 목록 높이를 넘을 때만 세로 스크롤을 표시한다."""
        if not self.tree.winfo_exists():
            return
        row_height = 23
        visible_rows = max(1, self.tree.winfo_height() // row_height)
        needed = len(self.tree.get_children()) > visible_rows
        visible = bool(self.tree_scrollbar.winfo_manager())
        if needed and not visible:
            self.tree_scrollbar.grid(row=0, column=1, sticky="ns")
        elif not needed and visible:
            self.tree_scrollbar.grid_remove()
        first, last = self.tree.yview()
        self.tree_scrollbar.set(first, last)

    def _schedule_tree_scrollbar_sync(self, _event=None) -> None:
        """레이아웃 완료 뒤 실제 행 높이가 반영된 범위로 다시 판정한다."""
        self.root.after_idle(self._sync_tree_scrollbar)

    def _make_readonly_text(self, parent: ttk.Frame, font: tuple | None = None) -> tk.Text:
        text = tk.Text(parent, wrap="none", font=font or ("맑은 고딕", 9), state="disabled")
        ybar = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
        xbar = ttk.Scrollbar(parent, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        text.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        return text

    def _center_window(self) -> None:
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = max(0, (self.root.winfo_screenwidth() - width) // 2)
        y = max(0, (self.root.winfo_screenheight() - height) // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        # Panedwindow의 weight는 초기 분할선 위치에 영향을 주지 않는다.
        # 검색 패널이 충분히 넓게 열리도록 첫 번째 sash를 직접 배치한다.
        try:
            self.main_pane.sashpos(0, 370)
        except tk.TclError:
            pass

    def _finish_startup(self) -> None:
        """창을 표시할 준비가 끝난 EXE 스플래시를 닫는다."""
        self._center_window()
        try:
            import pyi_splash
            pyi_splash.close()
        except (ImportError, RuntimeError):
            # .pyw 직접 실행과 스플래시를 쓰지 않는 빌드에서는 모듈이 없다.
            pass

    def _set_edit_state(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.condition_kind_combo.configure(state="readonly" if enabled else "disabled")
        self.condition_subkind_combo.configure(state="readonly" if enabled and CONDITION_GROUPS.get(self.condition_kind_var.get()) else "disabled")
        self.condition_edit_button.configure(state=state)
        self.condition_add_button.configure(state=state)
        self.condition_insert_button.configure(state=state)
        self.condition_remove_button.configure(state=state)
        self.condition_clear_button.configure(state=state)
        for spin in self.condition_value_spins:
            spin.configure(state=state)
        self.condition_target_combo.configure(state="readonly" if enabled else "disabled")

    @staticmethod
    def _resource_data_dir() -> Path:
        """독립 실행/개발 환경 모두에서 공용 추출 데이터 폴더를 찾는다."""
        project_dir = Path(__file__).resolve().parent
        candidates = (
            project_dir / "Resources" / "data",
            project_dir.parent / "Resources" / "data",
            project_dir.parent / "cds_save_editor" / "Resources" / "data",
        )
        return next((path for path in candidates if path.is_dir()), candidates[0])

    @staticmethod
    def _load_condition_targets(filename: str) -> list[tuple[int, str]]:
        """Load the already EXE-extracted target tables used by opcode 37."""
        path = DisevEditor._resource_data_dir() / filename
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return [(int(record["id"]), str(record["name"])) for record in data["records"]]
        except (OSError, ValueError, KeyError, TypeError):
            return []

    @staticmethod
    def _load_item_targets() -> list[tuple[int, str]]:
        """아이템 ID를 이름으로 표시한다. 발견물 보상 아이템은 발견물명을 사용한다."""
        data_dir = DisevEditor._resource_data_dir()
        path = data_dir / "master_data.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            # 기본 아이템표의 이름 없는 항목은 모두 발견물 보상 아이템이다.
            # 저장 에디터와 같이 해당 보상 발견물의 이름을 대신 표시한다.
            rewards = json.loads((data_dir / "discovery_reward_items.json").read_text(encoding="utf-8"))
            discovery_name_by_no = {
                int(record[0]): (str(record[1]) if record[1] is not None else "이름 미확인")
                for record in data["discovery_master_db"]
            }
            discovery_no_by_item_id = {
                int(item_id): int(discovery_no)
                for discovery_no, item_id in rewards["discovery_reward_item_ids"].items()
            }
            trade_goods = json.loads((data_dir / "trade_goods.json").read_text(encoding="utf-8"))
            trade_good_name_by_id = {
                int(record["id"]): str(record["name"])
                for record in trade_goods["records"]
            }
            discovery_trade_goods = json.loads(
                (data_dir / "discovery_trade_goods.json").read_text(encoding="utf-8")
            )["discovery_trade_good_ids"]

            def item_name(record: list[object]) -> str:
                item_id = int(record[0])
                if record[1] is not None:
                    return str(record[1])
                discovery_no = discovery_no_by_item_id.get(item_id)
                discovery_name = discovery_name_by_no.get(discovery_no, "")
                if discovery_name and discovery_name != "이름 미확인":
                    return discovery_name
                trade_good_id = discovery_trade_goods.get(str(discovery_no))
                return trade_good_name_by_id.get(int(trade_good_id), "이름 미확인")

            return [
                (int(record[0]), item_name(record))
                for record in data["item_master_db"]
            ]
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            return []

    @staticmethod
    def _load_city_targets() -> list[tuple[int, str]]:
        path = DisevEditor._resource_data_dir() / "city_data.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return [(int(record["index"]), str(record["name"])) for record in data["records"]]
        except (OSError, ValueError, KeyError, TypeError):
            return []

    @staticmethod
    def _load_nation_targets() -> list[tuple[int, str]]:
        try:
            path = DisevEditor._resource_data_dir() / "master_data.json"
            names = json.loads(path.read_text(encoding="utf-8"))["nation_names"]
            return [(index, str(name)) for index, name in enumerate(names) if name]
        except (OSError, ValueError, KeyError, TypeError):
            return []

    @staticmethod
    def _load_building_targets() -> list[tuple[int, str]]:
        try:
            path = DisevEditor._resource_data_dir() / "city_data.json"
            names = json.loads(path.read_text(encoding="utf-8"))["facility_names"]
            return [(int(item_id), str(name)) for item_id, name in names.items() if name]
        except (OSError, ValueError, KeyError, TypeError):
            return []

    @staticmethod
    def _load_culture_targets() -> list[tuple[int, str]]:
        """17 19 조건이 비교하는 현재 위치 객체의 문화권 ID 표를 읽는다."""
        try:
            path = DisevEditor._resource_data_dir() / "game_strings.json"
            records = json.loads(path.read_text(encoding="utf-8"))["city_cultures"]
            return [(int(record["id"]), str(record["name"])) for record in records]
        except (OSError, ValueError, KeyError, TypeError):
            return []

    @staticmethod
    def _load_discovery_targets(rows: list[disev.DiscoveryRow]) -> list[tuple[int, str]]:
        """발견물 등록 명령의 ID를 이름으로 표시한다.

        일반 발견물 외에 교역품 발견물(예: ID 207 = 정향)도 같은 상태
        배열을 공유한다. 이 레코드들은 EXE의 일반 발견물명 포인터가 비어
        있으므로 교역품 연결표에서 이름을 보완한다.
        """
        data_dir = DisevEditor._resource_data_dir()
        try:
            master = json.loads((data_dir / "master_data.json").read_text(encoding="utf-8"))
            goods = json.loads((data_dir / "trade_goods.json").read_text(encoding="utf-8"))
            links = json.loads(
                (data_dir / "discovery_trade_goods.json").read_text(encoding="utf-8")
            )["discovery_trade_good_ids"]
            good_names = {int(record["id"]): str(record["name"]) for record in goods["records"]}
            # `game_id`는 발견물 등록 opcode의 ID가 아니다. 예를 들어 향료제도
            # (레코드 4)와 정향(레코드 207)은 game_id가 모두 4다. 01 0B는
            # EXE 발견물 레코드의 순번(index)을 사용한다.
            names = {row.index: row.name for row in rows if row.name}
            for record in master["discovery_master_db"]:
                discovery_id = int(record[0])
                if discovery_id in names:
                    continue
                name = record[1]
                if name is None:
                    good_id = links.get(str(discovery_id))
                    name = good_names.get(int(good_id)) if good_id is not None else None
                if name:
                    names[discovery_id] = str(name)
            return list(names.items())
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            return [(row.index, row.name) for row in rows]

    @staticmethod
    def _load_hint_targets() -> list[tuple[int, str]]:
        """힌트 ID와 EXE에서 확인된 힌트명을 함께 표시할 목록을 불러온다."""
        project_dir = Path(__file__).resolve().parent
        data_dirs = (
            project_dir / "Resources" / "data",
            project_dir.parent / "Resources" / "data",
            # 개발 중인 이벤트 편집기는 저장 에디터와 같은 상위 폴더에 둘 수 있다.
            project_dir.parent / "cds_save_editor" / "Resources" / "data",
        )
        for data_dir in data_dirs:
            try:
                hint_data = json.loads((data_dir / "discovery_hint_data.json").read_text(encoding="utf-8"))
                records = hint_data["hints"]
                result = [
                    (int(record["id"]), str(record.get("name") or f"힌트 {record['id']}"))
                    for record in records
                ]
                if result:
                    return sorted(result)
            except (OSError, ValueError, KeyError, TypeError, IndexError):
                continue
        return []

    @staticmethod
    def _target_subtype(kind: str) -> int:
        return 0x0D if kind == "인물 조건" else 0x12

    def _condition_targets(self, subtype: int) -> list[tuple[int, str]]:
        return self.character_targets if subtype == 0x0D else self.sponsor_targets

    def _target_display(self, subtype: int, target_id: int) -> str:
        for item_id, name in self._condition_targets(subtype):
            if item_id == target_id:
                return f"{item_id} | {name}"
        return str(target_id)

    def _builder_condition_kind(self) -> str:
        """Return the original bytecode condition name selected by the grouped UI."""
        group = self.condition_kind_var.get()
        return CONDITION_GROUP_TO_KIND.get((group, self.condition_subkind_var.get()), group)

    def _condition_named_targets(self, kind: str) -> list[tuple[int, str]]:
        targets = {
            "국가": self.nation_targets,
            "도시": self.city_targets,
            "건물": self.building_targets,
            "문화권": self.culture_targets,
            "아이템 소지": self.item_targets,
            "아이템 비소지": self.item_targets,
            "힌트 상태 활성": self.hint_targets,
            "힌트 상태 미활성": self.hint_targets,
            "인물 조건": self.character_targets,
            "후원자 조건": self.sponsor_targets,
        }.get(kind, [])
        # -1은 발견물에 연결된 힌트가 없다는 표기이며 opcode의 u16 ID가 아니다.
        return [(target_id, name) for target_id, name in targets if target_id >= 0]

    def _refresh_condition_targets(self, kind: str) -> None:
        values = tuple(f"{item_id:03d} | {name}" for item_id, name in self._condition_named_targets(kind))
        self.condition_target_combo.configure(values=values)
        self._autosize_combobox(self.condition_target_combo)
        if values:
            self.condition_target_var.set(values[0])
        else:
            self.condition_target_var.set("")

    def _condition_kind_changed(self, _event=None) -> None:
        group = self.condition_kind_var.get()
        subkinds = CONDITION_GROUPS.get(group, ())
        self.condition_subkind_combo.configure(values=subkinds, state="readonly" if subkinds else "disabled")
        self._autosize_combobox(self.condition_kind_combo)
        self._autosize_combobox(self.condition_subkind_combo)
        if subkinds:
            if self.condition_subkind_var.get() not in subkinds:
                self.condition_subkind_var.set(subkinds[0])
            self.condition_subkind_label.grid(row=0, column=2, sticky="e")
            self.condition_subkind_combo.grid(row=0, column=3, sticky="w", padx=(5, 10))
        else:
            self.condition_subkind_var.set("")
            self.condition_subkind_label.grid_remove()
            self.condition_subkind_combo.grid_remove()
        kind = self._builder_condition_kind()
        spec = CONDITION_KINDS[kind]
        fields = spec[0]
        named_targets = self._condition_named_targets(kind)
        for index, (label, spin) in enumerate(zip(self.condition_value_labels, self.condition_value_spins)):
            if index < len(fields) and not named_targets:
                title, minimum, maximum = fields[index]
                label.configure(text=f"{title}:")
                spin.configure(from_=minimum, to=maximum)
                base_column = 4 if subkinds else 2
                label.grid(row=0, column=base_column + index * 2, sticky="e")
                spin.grid(row=0, column=base_column + index * 2 + 1, sticky="w", padx=(4, 8))
            else:
                label.grid_remove()
                spin.grid_remove()
        if named_targets:
            base_column = 4 if subkinds else 2
            label_text = "힌트:" if kind.startswith("힌트") else "대상:"
            self.condition_target_label.configure(text=label_text)
            self.condition_target_label.grid(row=0, column=base_column, sticky="e")
            self.condition_target_combo.grid(row=0, column=base_column + 1, columnspan=3, sticky="w", padx=(4, 8))
            self._refresh_condition_targets(kind)
        else:
            self.condition_target_label.grid_remove()
            self.condition_target_combo.grid_remove()
        self.condition_summary_var.set("조건을 고른 뒤 [추가]를 누르세요. 조건을 나열하면 AND, '또는 (OR)'는 OR입니다.")

    def _decode_condition_tokens(self, condition: bytes) -> list[tuple[str, tuple[int, ...]]] | None:
        if not condition.endswith(b"\xFF"):
            return None
        code = condition[:-1]
        tokens: list[tuple[str, tuple[int, ...]]] = []
        offset = 0
        while offset < len(code):
            if code[offset] == 0x50:
                if not tokens or tokens[-1][0] == "또는 (OR)":
                    return None
                tokens.append(("또는 (OR)", ()))
                offset += 1
                continue
            if code.startswith(b"\x5A", offset):
                tokens.append(("후원자 계약 없음", ()))
                offset += 1
                continue
            if offset + 4 <= len(code):
                primary, secondary = code[offset], code[offset + 1]
                value = struct.unpack_from("<H", code, offset + 2)[0]
                if primary == 0x17 and secondary in (0x00, 0x08, 0x10, 0x19):
                    tokens.append(({0x00: "국가", 0x08: "도시", 0x10: "건물", 0x19: "문화권"}[secondary], (value,)))
                    offset += 4
                    continue
                if secondary == 0x05 and primary in (0x12, 0x0F):
                    tokens.append(("아이템 소지" if primary == 0x12 else "아이템 비소지", (value,)))
                    offset += 4
                    continue
                if secondary == 0x0E and primary in (0x12, 0x0F):
                    tokens.append(("힌트 상태 미활성" if primary == 0x12 else "힌트 상태 활성", (value,)))
                    offset += 4
                    continue
                if primary == 0x37 and secondary in (0x0D, 0x12):
                    tokens.append(("인물 조건" if secondary == 0x0D else "후원자 조건", (value,)))
                    offset += 4
                    continue
                if secondary == 0x16 and primary in (0x1B, 0x1C):
                    tokens.append(("기준 연도 이후" if primary == 0x1B else "기준 연도 이전", (value,)))
                    offset += 4
                    continue
            if offset + 6 <= len(code) and code[offset : offset + 2] == b"\x1B\x17" and code[offset + 3] == 0x16:
                tokens.append(("특정 연·월", (code[offset + 2], struct.unpack_from("<H", code, offset + 4)[0])))
                offset += 6
                continue
            if offset + 7 <= len(code) and code[offset : offset + 2] == b"\x36\x16" and code[offset + 4] == 0x16:
                tokens.append(("연도 범위", (struct.unpack_from("<H", code, offset + 2)[0], struct.unpack_from("<H", code, offset + 5)[0])))
                offset += 7
                continue
            if (
                offset + 11 <= len(code)
                and code[offset : offset + 2] == b"\x2E\x1A"
                and code[offset + 6] == 0x1A
            ):
                denominator = struct.unpack_from("<I", code, offset + 2)[0]
                success_count = struct.unpack_from("<I", code, offset + 7)[0]
                if denominator < 1 or success_count != 1:
                    return None
                tokens.append(("무작위 확률", (denominator,)))
                offset += 11
                continue
            return None
        return tokens if not tokens or tokens[-1][0] != "또는 (OR)" else None

    def _condition_value_columns(self, kind: str, values: tuple[int, ...]) -> tuple[str, str]:
        if kind == "또는 (OR)":
            return "-", "-"
        named_targets = self._condition_named_targets(kind)
        if named_targets:
            target_id = values[0] if values else -1
            name = next((candidate_name for candidate_id, candidate_name in named_targets
                         if candidate_id == target_id), None)
            # 목록은 스크립트를 읽기 위한 화면이므로 내부 ID 대신 이름을 보인다.
            # 이름 표가 없는 원본 ID만 예외적으로 그대로 남겨 손실을 알린다.
            return name if name is not None else str(target_id), "-"
        fields = CONDITION_KINDS[kind][0]
        if not fields:
            return "-", "-"
        value1 = str(values[0]) if values else "-"
        value2 = str(values[1]) if len(values) > 1 else "-"
        return value1, value2

    @staticmethod
    def _classification_label(*levels: str, separator: str = "/") -> str:
        """Render only the classification levels that are actually present."""
        return separator.join(level for level in levels if level)

    def _condition_display_levels(self, kind: str) -> tuple[str, str]:
        group, subkind = CONDITION_KIND_TO_GROUP.get(kind, (kind, ""))
        return group, subkind

    def _condition_remark_text(self, kind: str, values: tuple[int, ...]) -> str:
        if kind == "무작위 확률":
            return f"1 / {values[0]}"
        if kind in ("인물 조건", "후원자 조건"):
            subtype = self._target_subtype(kind)
            for item_id, name in self._condition_targets(subtype):
                if item_id == values[0]:
                    return name
            return "-"
        if kind in ("기준 연도 이후", "기준 연도 이전"):
            return f"{values[0]}년"
        if kind == "특정 연·월":
            return f"{values[1]}년 {values[0]}월"
        if kind == "연도 범위":
            return f"{values[0]}년 ~ {values[1]}년"
        return "-"

    def _refresh_condition_display(self, select_index: int | None = None) -> None:
        self.condition_tree.delete(*self.condition_tree.get_children())
        self.selected_condition_index = None
        if self.condition_tokens is None:
            self.condition_tree.insert("", "end", iid="message", values=("-", "미확인", "-", "-", "-", "미확인 또는 복합 opcode가 포함된 조건입니다."))
            self.root.after_idle(lambda: self._autosize_tree_columns(self.condition_tree, skip=("remark",)))
            return
        if not self.condition_tokens:
            self.condition_tree.insert("", "end", iid="empty", values=("-", "조건 없음", "-", "-", "-", "항상 발생"))
            self.root.after_idle(lambda: self._autosize_tree_columns(self.condition_tree, skip=("remark",)))
            return
        for index, (kind, values) in enumerate(self.condition_tokens):
            value1, value2 = self._condition_value_columns(kind, values)
            primary, secondary = self._condition_display_levels(kind)
            self.condition_tree.insert(
                "", "end", iid=str(index),
                values=(index + 1, primary, secondary or "-", value1, value2, self._condition_remark_text(kind, values)),
            )
        if select_index is not None and 0 <= select_index < len(self.condition_tokens):
            item = str(select_index)
            self.condition_tree.selection_set(item)
            self.condition_tree.focus(item)
            self.condition_tree.see(item)
        self.root.after_idle(lambda: self._autosize_tree_columns(self.condition_tree, skip=("remark",)))

    def _select_condition(self, _event=None) -> None:
        if self.condition_tokens is None:
            return
        selected = self.condition_tree.selection()
        if not selected or not selected[0].isdigit():
            self.selected_condition_index = None
            return
        index = int(selected[0])
        if not 0 <= index < len(self.condition_tokens):
            return
        self.selected_condition_index = index
        kind, values = self.condition_tokens[index]
        group, subkind = CONDITION_KIND_TO_GROUP.get(kind, (kind, ""))
        self.condition_kind_var.set(group)
        self.condition_subkind_var.set(subkind)
        self._condition_kind_changed()
        if self._condition_named_targets(kind):
            prefix = f"{values[0]:03d} |"
            for candidate in self.condition_target_combo.cget("values"):
                if str(candidate).startswith(prefix):
                    self.condition_target_var.set(candidate)
                    break
        else:
            for value_index, value in enumerate(values):
                self.condition_value_vars[value_index].set(str(value))

    def _select_body_command(self, _event=None) -> None:
        selected = self.body_tree.selection()
        if not selected or not selected[0].isdigit():
            return
        index = int(selected[0])
        if not 0 <= index < len(self.body_tokens):
            return
        self.selected_body_index = index
        token = self.body_tokens[index]
        kind = str(token["kind"])
        value = token.get("value")
        group, subkind = BODY_KIND_TO_GROUP.get(kind, (kind, ""))
        self.body_command_var.set(group if group in BODY_COMMAND_GROUPS else "")
        self.body_subkind_var.set(subkind)
        self.body_detail_var.set(BODY_KIND_TO_DETAIL.get(kind, ""))
        if kind == HINT_BRANCH_KIND:
            self.body_detail_var.set("활성" if token.get("hint_active", True) else "미활성")
        elif kind == DISCOVERY_BRANCH_KIND:
            discovery_id = int(token["character_id"])
            discovery_name = next((name for candidate_id, name in self.discovery_targets if candidate_id == discovery_id), str(discovery_id))
            self.body_detail_var.set(self._body_target_display(discovery_id, discovery_name))
        elif kind == DISCOVERY_REGISTRATION_BRANCH_KIND:
            discovery_id = int(token["character_id"])
            discovery_name = next((name for candidate_id, name in self.discovery_targets if candidate_id == discovery_id), str(discovery_id))
            self.body_detail_var.set(self._body_target_display(discovery_id, discovery_name))
        elif kind == CITY_BRANCH_KIND:
            self._set_body_city(int(token["character_id"]))
        elif kind == NPC_BRANCH_KIND:
            npc_type = int(token.get("npc_type", 0x0D))
            self.body_detail_var.set("인물" if npc_type == 0x0D else "후원자")
            self._set_body_npc(int(token["character_id"]), self.sponsor_targets if npc_type == 0x12 else self.character_targets)
        elif kind in (ITEM_POSSESSION_BRANCH_KIND, ITEM_ABSENCE_BRANCH_KIND):
            self._set_body_item(int(token["item_id"]))
        elif kind in NUMERIC_COMPARE_BRANCH_KINDS + (STATE_REFERENCE_COMPARE_BRANCH_KIND,) or kind in STAT_REFERENCE_COMMAND_KINDS:
            self.body_stat_target_var.set(STAT_TARGET_NAMES.get(int(token["stat_id"]), "미사용/미확인"))
        display_value = token.get("value_text", value)
        self.body_value2_var.set("")
        self.body_random_var.set(False)
        if kind in RANDOM_STATE_COMPARE_BRANCH_KINDS:
            self.body_random_var.set(True)
        if kind in RANDOM_RANGE_COMMAND_KINDS + RANDOM_STATE_COMPARE_BRANCH_KINDS and isinstance(display_value, str) and "~" in display_value:
            first, second = display_value.split("~", 1)
            self.body_value_var.set(first)
            self.body_value2_var.set(second)
            self.body_random_var.set(True)
            self.body_random_var.set(True)
        else:
            self.body_value_var.set("" if display_value is None else str(display_value))
        if kind == "소지금 비교 분기":
            self.body_value2_var.set(str(token["compare_value"]))
        elif kind == RUNTIME_REFERENCE_BRANCH_KIND:
            self.body_value2_var.set(str(token["threshold"]))
            self.body_range_end_var.set(str(token["runtime_id"]))
        editable = bool(token["editable"])
        self._body_kind_changed()
        if kind in DIALOGUE_KINDS:
            self._set_body_speaker(bytes(token.get("speaker_prefix", b"")))
        if kind == "대상 지정 대사":
            self._set_body_npc(int(token["character_id"]))
        if kind == "발견물 이름 설정":
            self._set_body_character(int(token["character_id"]))
        if kind == "발견물 등록/발견 처리":
            self._set_body_character(int(value))
        if kind in CHARACTER_TARGET_COMMAND_KINDS:
            self._set_body_npc(int(token["character_id"]))
        if kind in ("아이템 획득", "아이템 상실", "이벤트 아이템 등록", "이벤트 아이템 처리"):
            self._set_body_item(int(value))
        if kind in (ITEM_POSSESSION_BRANCH_KIND, ITEM_ABSENCE_BRANCH_KIND):
            self._set_body_item(int(token["item_id"]))
        if kind == "신도시 생성":
            self._set_body_city(int(value))
        if kind == "이벤트 결과 코드":
            self._set_body_result(int(value))
        if kind in STAT_COMMAND_KINDS:
            self._set_body_stat_target(int(token["stat_id"]))
        if kind in STAT_REFERENCE_COMMAND_KINDS:
            self._set_body_stat_target(int(token["stat_id"]))
            self.body_value_var.set(str(token["source_stat_id"]))
        if kind in NUMERIC_COMPARE_BRANCH_KINDS:
            self._set_body_stat_target(int(token["stat_id"]))
            self.body_value2_var.set(str(token.get("compare_value_text", token["compare_value"])))
        if kind == STATE_REFERENCE_COMPARE_BRANCH_KIND:
            self._set_body_stat_target(int(token["stat_id"]))
            self.body_value2_var.set(str(token["source_stat_id"]))
        if kind == CHOICE_BRANCH_KIND:
            self.body_value2_var.set(str(token["choice_value"]))
        if kind == "특수 수치 판정":
            self.special_check_value_var.set(str(token["value"]))
            self.special_difficulty_var.set(str(token["difficulty"]))
        if kind == HINT_BRANCH_KIND:
            self._set_body_hint(int(token["hint_id"]))
            self.body_hint_state_var.set("활성" if token.get("hint_active", True) else "미활성")
        if kind == "힌트 획득":
            self._set_body_hint(int(value))
        if kind == DISCOVERY_BRANCH_KIND:
            self._set_body_character(int(token["character_id"]))
        if kind == DISCOVERY_REGISTRATION_BRANCH_KIND:
            self._set_body_character(int(token["character_id"]))
        if kind == YEAR_RANGE_BRANCH_KIND:
            self.body_value2_var.set(str(token["start_year"]))
            self.body_range_end_var.set(str(token["end_year"]))
        if kind in (YEAR_BRANCH_KIND, YEAR_UPPER_BRANCH_KIND):
            self.body_value2_var.set(str(token["year"]))
        if kind == CITY_BRANCH_KIND:
            self._set_body_city(int(token["character_id"]))
        if kind == NPC_BRANCH_KIND:
            npc_type = int(token.get("npc_type", 0x0D))
            self._set_body_npc(int(token["character_id"]), self.sponsor_targets if npc_type == 0x12 else self.character_targets)
        self.body_kind_combo.configure(state="readonly" if editable else "disabled")
        self.body_subkind_combo.configure(state="readonly" if editable and BODY_COMMAND_GROUPS.get(group) else "disabled")
        self.body_detail_combo.configure(
            state="readonly" if editable and (
                group == "미디어" or (group == "행 이동" and bool(MOVE_SUBKINDS.get(subkind)))
            ) else "disabled"
        )
        needs_value = kind not in ("음원 정지", "이미지 표시 종료", "대화창 숨김", "대화창 표시", "결과 거짓 설정", "결과 참 설정", "주인공 성격 판정")
        self.body_value_entry.configure(state="normal" if editable and needs_value else "disabled")
        self.body_value2_entry.configure(
            state="normal" if editable and (
                kind in NUMERIC_COMPARE_BRANCH_KINDS + (CHOICE_BRANCH_KIND, "특수 수치 판정")
                or (kind in RANDOM_RANGE_COMMAND_KINDS and self.body_random_var.get())
            ) else "disabled"
        )
        self.body_speaker_combo.configure(state="readonly" if editable and kind in DIALOGUE_KINDS else "disabled")
        self.body_character_combo.configure(
            state="readonly" if editable and kind in ("발견물 등록/발견 처리", DISCOVERY_BRANCH_KIND, NPC_BRANCH_KIND) else "disabled"
        )
        self.body_item_combo.configure(state="readonly" if editable and kind in ("아이템 획득", "아이템 상실", "이벤트 아이템 등록", "이벤트 아이템 처리") else "disabled")
        self.body_city_combo.configure(state="readonly" if editable and kind == "신도시 생성" else "disabled")
        self.body_stat_target_combo.configure(state="readonly" if editable and kind in STAT_COMMAND_KINDS + NUMERIC_COMPARE_BRANCH_KINDS else "disabled")
        self.body_hint_state_combo.configure(state="readonly" if editable and kind == HINT_BRANCH_KIND else "disabled")
        self.body_hint_combo.configure(state="readonly" if editable and kind in (HINT_BRANCH_KIND, "힌트 획득") else "disabled")
        self.body_edit_button.configure(state="normal" if editable else "disabled")
        self.status_var.set(ui("status_body_selected", index + 1))

    def _body_kind_changed(self, _event=None) -> None:
        group = self.body_command_var.get()
        subkinds = BODY_COMMAND_GROUPS.get(group, ())
        self.body_subkind_combo.configure(values=subkinds, state="readonly" if subkinds else "disabled")
        self._autosize_combobox(self.body_kind_combo)
        self._autosize_combobox(self.body_subkind_combo)
        if subkinds and self.body_subkind_var.get() not in subkinds:
            self.body_subkind_var.set(subkinds[0])
        elif not subkinds:
            self.body_subkind_var.set("")
        if group == "미디어":
            detail_kinds = MEDIA_SUBKINDS.get(self.body_subkind_var.get(), ())
        elif group == "행 이동":
            if self.body_subkind_var.get() == "발견물":
                detail_kinds = MOVE_SUBKINDS["발견물"]
            elif self.body_subkind_var.get() == "NPC 조건":
                detail_kinds = ("인물", "후원자")
            else:
                detail_kinds = MOVE_SUBKINDS.get(self.body_subkind_var.get(), ())
        elif group == "상태값":
            # 상태값 명령의 대상은 3차 분류로 선택한다.
            detail_kinds = tuple(name for _target_id, name in STAT_TARGETS)
        else:
            detail_kinds = ()
        self.body_detail_combo.configure(values=detail_kinds, state="readonly" if detail_kinds else "disabled")
        self._autosize_combobox(self.body_detail_combo)
        if detail_kinds and self.body_detail_var.get() not in detail_kinds:
            self.body_detail_var.set(detail_kinds[0])
        elif not detail_kinds:
            self.body_detail_var.set("")
        if group == "행 이동" and self.body_subkind_var.get() == "힌트 상태":
            self.body_hint_state_var.set(self.body_detail_var.get())
        elif group == "행 이동" and self.body_subkind_var.get() == "발견물":
            if not self.body_character_var.get() and self.discovery_targets:
                self._set_body_character(self.discovery_targets[0][0])
        if group == "미디어" and self.body_detail_var.get() in detail_kinds:
            kind = MEDIA_DETAIL_TO_KIND[(self.body_subkind_var.get(), self.body_detail_var.get())]
        elif group == "행 이동" and (self.body_subkind_var.get(), self.body_detail_var.get()) in MOVE_DETAIL_TO_KIND:
            kind = MOVE_DETAIL_TO_KIND[(self.body_subkind_var.get(), self.body_detail_var.get())]
        else:
            kind = BODY_GROUP_TO_KIND.get((group, self.body_subkind_var.get()), BODY_GROUP_TO_KIND.get((group, ""), group))
        # 2B 형식은 무작위 기준값만 지원하므로 선택 즉시 범위 입력을 켠다.
        if kind == STATE_GREATER_RANDOM_BRANCH_KIND:
            self.body_random_var.set(True)
        is_dialogue = kind in DIALOGUE_KINDS
        is_character_dialogue = kind == "발견물 이름 설정"
        is_discovery_registration = kind == "발견물 등록/발견 처리"
        is_discovery_branch = kind in (DISCOVERY_BRANCH_KIND, DISCOVERY_REGISTRATION_BRANCH_KIND)
        is_npc_branch = kind == NPC_BRANCH_KIND
        is_hint_branch = kind == HINT_BRANCH_KIND
        is_hint_grant = kind == "힌트 획득"
        is_choice_branch = kind == CHOICE_BRANCH_KIND
        is_special_value_check = kind == "특수 수치 판정"
        is_state_compare_branch = kind in NUMERIC_COMPARE_BRANCH_KINDS
        is_branch = kind in ("결과 거짓 시 이동", "결과 참 시 이동", "이전 조건 참 시 이동", "특수 분기", CHOICE_BRANCH_KIND, HINT_BRANCH_KIND, DISCOVERY_BRANCH_KIND, DISCOVERY_REGISTRATION_BRANCH_KIND, CITY_BRANCH_KIND, NPC_BRANCH_KIND) + NUMERIC_COMPARE_BRANCH_KINDS
        is_stat = kind in STAT_COMMAND_KINDS
        is_date_passage = kind == "날짜 경과"
        is_random_range = kind in RANDOM_RANGE_COMMAND_KINDS
        is_item = kind in ("아이템 획득", "아이템 상실", "이벤트 아이템 등록", "이벤트 아이템 처리")
        is_city = kind == "신도시 생성"
        is_event_result = kind == "이벤트 결과 코드"
        self._rebuild_body_command_controls(kind, group, subkinds, detail_kinds)
        self.root.after_idle(self._autosize_all_comboboxes)
        return
        # 명령 종류를 바꿀 때 이전 종류의 grid 위치가 남아 있으면 같은 열에
        # 위젯이 겹친다. 가변 입력 위젯을 먼저 모두 숨긴 뒤 필요한 것만 다시 배치한다.
        for widget in (
            self.body_value_label, self.body_value_entry,
            self.body_subkind_label, self.body_subkind_combo, self.body_detail_label, self.body_detail_combo,
            self.body_value2_label, self.body_value2_plain_label, self.body_value2_entry,
            self.special_check_value_label, self.special_check_value_entry,
            self.special_difficulty_label, self.special_difficulty_entry,
            self.body_stat_target_label, self.body_stat_target_combo,
            self.body_speaker_label, self.body_speaker_combo,
            self.body_character_label, self.body_character_combo, self.body_character_entry,
            self.body_hint_state_label, self.body_hint_state_combo,
            self.body_hint_label, self.body_hint_combo,
            self.body_item_combo, self.body_city_combo, self.body_result_combo,
        ):
            widget.grid_remove()
        if subkinds:
            self.body_subkind_label.grid(row=0, column=2, sticky="w")
            self.body_subkind_combo.grid(row=0, column=3, sticky="w", padx=(5, 10))
        if detail_kinds:
            self.body_detail_label.configure(text="3차:")
            self.body_detail_label.grid(row=0, column=4, sticky="w")
            self.body_detail_combo.grid(row=0, column=5, sticky="w", padx=(5, 10))
        elif is_dialogue:
            self.body_detail_label.configure(text="화자:")
            self.body_detail_label.grid(row=0, column=4, sticky="w")
            self.body_speaker_combo.grid(row=0, column=5, sticky="w", padx=(5, 10))
        self.body_action_row.grid_configure(row=1)
        # 대상 콤보는 고정하고, 상태값의 두 수치 칸만 남는 폭을 균등하게 확장한다.
        self.body_value_entry.master.columnconfigure(3, weight=0)
        self.body_value_entry.master.columnconfigure(3, weight=1 if is_date_passage else 0, uniform="range_values" if is_date_passage else "")
        self.body_value_entry.master.columnconfigure(5, weight=1 if (is_stat or is_date_passage or is_special_value_check) else 0, uniform="range_values" if (is_stat or is_date_passage or is_special_value_check) else "")
        self.body_value_entry.master.columnconfigure(7, weight=1 if is_stat else 0, uniform="range_values" if is_stat else "")
        value_label = (
            "이동할 행:" if is_branch else
            "대사:" if is_dialogue else
            "이름:" if is_character_dialogue else
            "아이템:" if is_item else
            "도시:" if is_city else
            "발견물:" if is_discovery_registration else
            "처리:" if is_event_result else
            "판정 종류:" if kind == "이벤트 판정" else
            "설정값:" if kind == "상태값 설정" else
            "일수:" if is_date_passage else
            "수치:" if is_stat else "값:"
        )
        self.body_value_label.configure(text=value_label)
        # 상태값 명령은 "대상 → 수치/설정값" 순서로 읽히도록 배치한다.
        if is_hint_branch:
            self.body_hint_state_label.grid(row=0, column=2, sticky="e", padx=(10, 0))
            self.body_hint_state_combo.grid(row=0, column=3, sticky="w", padx=(5, 12))
            self.body_hint_label.grid(row=0, column=4, sticky="e")
            self.body_hint_combo.grid(row=0, column=5, sticky="w", padx=(5, 12))
            self.body_value_label.grid(row=0, column=6, sticky="e")
            self.body_value_entry.configure(width=8)
            self.body_value_entry.grid(row=0, column=7, sticky="w", padx=(5, 0))
            if not self.body_hint_var.get() and self.hint_targets:
                self._set_body_hint(self.hint_targets[0][0])
        elif is_hint_grant:
            self.body_hint_label.grid(row=0, column=2, sticky="e")
            self.body_hint_combo.grid(row=0, column=3, sticky="ew", padx=(5, 0))
            if not self.body_hint_var.get() and self.hint_targets:
                self._set_body_hint(self.hint_targets[0][0])
        elif is_discovery_branch:
            self.body_character_label.configure(text="대상 발견물:")
            self.body_character_label.grid(row=0, column=2, sticky="e")
            self.body_character_combo.grid(row=0, column=3, sticky="ew", padx=(5, 12))
            self.body_value_label.grid(row=0, column=4, sticky="e")
            self.body_value_entry.configure(width=8)
            self.body_value_entry.grid(row=0, column=5, sticky="w", padx=(5, 0))
            if not self.body_character_var.get() and self.discovery_targets:
                self._set_body_character(self.discovery_targets[0][0])
        elif is_state_compare_branch:
            if group == "상태값":
                self.body_stat_target_label.grid(row=0, column=4, sticky="e")
                self.body_stat_target_combo.grid(row=0, column=5, sticky="w", padx=(5, 10))
                self.body_value2_plain_label.configure(text="기준값:")
                self.body_value2_plain_label.grid(row=0, column=6, sticky="e")
                self.body_value2_entry.configure(width=10)
                self.body_value2_entry.grid(row=0, column=7, sticky="w", padx=(5, 8))
                self.body_value2_label.grid(row=0, column=8, sticky="w")
                self.body_value_label.configure(text="이동할 행:")
                self.body_value_label.grid(row=0, column=9, sticky="e")
                self.body_value_entry.configure(width=7)
                self.body_value_entry.grid(row=0, column=10, sticky="w", padx=(5, 0))
            else:
                self.body_stat_target_label.grid(row=0, column=2, sticky="e")
                self.body_stat_target_combo.grid(row=0, column=3, sticky="w", padx=(5, 12))
                self.body_value2_plain_label.grid(row=0, column=4, sticky="e")
                self.body_value2_entry.configure(width=12)
                self.body_value2_entry.grid(row=0, column=5, sticky="w", padx=(5, 12))
                self.body_value_label.configure(text="이동할 행:")
                self.body_value_label.grid(row=0, column=6, sticky="e")
                self.body_value_entry.configure(width=8)
                self.body_value_entry.grid(row=0, column=7, sticky="w", padx=(5, 0))
            if not self.body_stat_target_var.get():
                self._set_body_stat_target(STAT_TARGETS[0][0])
        elif is_choice_branch:
            self.body_value2_plain_label.configure(text="선택값:")
            self.body_value2_plain_label.grid(row=0, column=2, sticky="e")
            self.body_value2_entry.configure(width=8)
            self.body_value2_entry.grid(row=0, column=3, sticky="w", padx=(5, 12))
            self.body_value_label.configure(text="이동할 행:")
            self.body_value_label.grid(row=0, column=4, sticky="e")
            self.body_value_entry.configure(width=8)
            self.body_value_entry.grid(row=0, column=5, sticky="w", padx=(5, 0))
        elif is_special_value_check:
            self.body_value_label.configure(text="판정값:")
            self.body_value_label.grid(row=0, column=2, sticky="e")
            self.body_value_entry.configure(width=14)
            self.body_value_entry.grid(row=0, column=3, sticky="ew", padx=(5, 12))
            self.body_value2_plain_label.configure(text="난이도:")
            self.body_value2_plain_label.grid(row=0, column=4, sticky="e")
            self.body_value2_entry.configure(width=14)
            self.body_value2_entry.grid(row=0, column=5, sticky="ew", padx=(5, 0))
        elif is_stat:
            self.body_stat_target_label.grid(row=0, column=2, sticky="e", padx=(10, 0))
            self.body_stat_target_combo.grid(row=0, column=3, sticky="w", padx=(5, 14))
            self.body_value_label.configure(text="수치 1:")
            self.body_value_label.grid(row=0, column=4, sticky="e", padx=(0, 0))
            self.body_value_entry.configure(width=14)
            self.body_value_entry.grid(row=0, column=5, sticky="ew", padx=(5, 10))
            self.body_value2_label.grid(row=0, column=6, sticky="w")
            self.body_value2_entry.configure(width=14)
            self.body_value2_entry.grid(row=0, column=7, sticky="ew", padx=(5, 0))
        elif is_date_passage:
            self.body_value_label.configure(text="일수:")
            self.body_value_label.grid(row=0, column=2, sticky="e")
            self.body_value_entry.configure(width=14)
            self.body_value_entry.grid(row=0, column=3, sticky="ew", padx=(5, 10))
            self.body_value2_label.grid(row=0, column=4, sticky="w")
            self.body_value2_entry.configure(width=14)
            self.body_value2_entry.grid(row=0, column=5, sticky="ew", padx=(5, 0))
        elif is_character_dialogue:
            # 발견물 이름 설정은 무엇의 이름을 바꾸는지가 먼저 와야 한다.
            # "대상 발견물 → 이름" 순서로 고정한다.
            self.body_character_label.grid(row=0, column=2, sticky="e")
            self.body_character_entry.grid(row=0, column=3, sticky="ew", padx=(5, 14))
            self.body_value_label.grid(row=0, column=4, sticky="e", padx=(10, 0))
            self.body_value_entry.grid(row=0, column=5, sticky="ew", padx=(5, 0))
        elif is_dialogue:
            # 화자는 3차 분류 자리에서 고른다.
            self.body_speaker_label.grid_remove()
            self.body_speaker_combo.grid(row=0, column=5, sticky="w", padx=(5, 10))
            self.body_value_label.grid(row=0, column=4, sticky="e", padx=(10, 0))
            self.body_value_entry.grid(row=0, column=5, sticky="ew", padx=(5, 0))
        else:
            self.body_value_label.grid(row=0, column=2, sticky="e")
            self.body_value_entry.configure(width=28)
        self.body_item_combo.grid_remove()
        self.body_city_combo.grid_remove()
        self.body_result_combo.grid_remove()
        self.body_character_entry.grid_remove()
        if not is_hint_branch:
            self.body_hint_state_label.grid_remove()
            self.body_hint_state_combo.grid_remove()
        if not (is_hint_branch or is_hint_grant):
            self.body_hint_label.grid_remove()
            self.body_hint_combo.grid_remove()
        if not is_random_range and not is_state_compare_branch and not is_choice_branch:
            self.body_value2_label.grid_remove()
            self.body_value2_entry.grid_remove()
        if not is_state_compare_branch and not is_choice_branch:
            self.body_value2_plain_label.grid_remove()
        if is_item:
            self.body_value_entry.grid_remove()
            self.body_item_combo.grid(row=0, column=3, sticky="ew", padx=(5, 0))
            self.body_item_combo.configure(state="readonly")
            if not self.body_item_var.get() and self.item_targets:
                self._set_body_item(self.item_targets[0][0])
        elif is_city:
            self.body_value_entry.grid_remove()
            self.body_city_combo.grid(row=0, column=3, sticky="ew", padx=(5, 0))
            self.body_city_combo.configure(state="readonly")
            if not self.body_city_var.get() and self.city_targets:
                self._set_body_city(self.city_targets[0][0])
        elif is_discovery_registration:
            self.body_value_entry.grid_remove()
            self.body_character_combo.grid(row=0, column=3, sticky="ew", padx=(5, 0))
            self.body_character_combo.configure(state="readonly")
            if not self.body_character_var.get() and self.discovery_targets:
                self._set_body_character(self.discovery_targets[0][0])
        elif is_event_result:
            self.body_value_entry.grid_remove()
            self.body_result_combo.grid(row=0, column=3, sticky="ew", padx=(5, 0))
            self.body_result_combo.configure(state="readonly")
        elif not is_stat and not is_date_passage and not is_character_dialogue and not is_dialogue and not is_hint_branch and not is_hint_grant and not is_discovery_branch and not is_state_compare_branch and not is_choice_branch:
            self.body_value_entry.grid(row=0, column=3, sticky="ew", padx=(5, 0))
        needs_value = kind not in ("음원 정지", "이미지 표시 종료", "대화창 숨김", "대화창 표시", "결과 거짓 설정", "결과 참 설정")
        self.body_value_entry.configure(
            state="normal" if needs_value and not (is_item or is_city or is_discovery_registration or is_event_result) else "disabled"
        )
        # 통합 명령은 "1차 → 2차 → 값"을 한 줄에 둔다.
        if subkinds and not is_state_compare_branch:
            # 결과 설정은 플래그만 바꾸므로 별도 입력값을 받지 않는다.
            if kind in ("음원 정지", "이미지 표시 종료", "결과 거짓 설정", "결과 참 설정"):
                self.body_value_label.grid_remove()
                self.body_value_entry.grid_remove()
            else:
                self.body_value_label.grid(row=0, column=4, sticky="e", padx=(0, 0))
                if is_item:
                    self.body_item_combo.grid(row=0, column=5, sticky="ew", padx=(5, 0))
                elif is_discovery_registration:
                    self.body_character_combo.grid(row=0, column=5, sticky="ew", padx=(5, 0))
                else:
                    self.body_value_entry.grid(row=0, column=5, sticky="ew", padx=(5, 0))
        self.body_value2_entry.configure(
            state="normal" if is_special_value_check or is_state_compare_branch or (is_random_range and self.body_random_var.get()) else "disabled"
        )
        self.body_value2_label.configure(
            state="normal" if is_state_compare_branch or is_random_range else "disabled"
        )
        if kind == "이벤트 결과 코드" and not self.body_value_var.get().strip():
            self.body_value_var.set("0")
        if is_dialogue and not self.body_speaker_var.get():
            self.body_speaker_var.set("화자 없음")
        self._arrange_body_editor_rows(kind)
        self._hide_disabled_body_inputs()

    def _rebuild_body_command_controls(
        self, kind: str, group: str, subkinds: tuple[str, ...], detail_kinds: tuple[str, ...],
    ) -> None:
        """Create only the final command's own controls; never reuse a shared input row."""
        for child in self.body_input_row.winfo_children():
            child.destroy()

        # 분류행: 마지막 분류가 정해진 뒤에만 그에 맞는 선택기를 표시한다.
        for widget in (self.body_subkind_label, self.body_subkind_combo, self.body_detail_label, self.body_detail_combo, self.body_fourth_label, self.body_fourth_combo, self.body_speaker_label, self.body_speaker_combo):
            widget.grid_remove()
        if subkinds:
            self.body_subkind_label.grid(row=0, column=2, sticky="w")
            self.body_subkind_combo.grid(row=0, column=3, sticky="w", padx=(5, 10))
        if detail_kinds:
            self.body_detail_label.configure(text="3차:")
            self.body_detail_label.grid(row=0, column=4, sticky="w")
            self.body_detail_combo.grid(row=0, column=5, sticky="w", padx=(5, 10))
            if group == "행 이동" and self.body_subkind_var.get() == "힌트 상태":
                self.body_fourth_label.grid(row=0, column=6, sticky="w")
                self.body_fourth_label.configure(text="4차:")
                self.body_fourth_combo.configure(
                    textvariable=self.body_hint_var,
                    values=tuple(
                        self._body_target_display(hint_id, name)
                        for hint_id, name in self.hint_targets if hint_id >= 0
                    )
                )
                self.body_fourth_combo.grid(row=0, column=7, sticky="w", padx=(5, 10))
            elif group == "행 이동" and self.body_subkind_var.get() == "상태값":
                self.body_fourth_label.grid(row=0, column=6, sticky="w")
                self.body_fourth_label.configure(text="4차:")
                self.body_fourth_combo.configure(
                    textvariable=self.body_stat_target_var,
                    values=tuple(name for _target_id, name in STAT_TARGETS),
                )
                self.body_fourth_combo.grid(row=0, column=7, sticky="w", padx=(5, 10))
            elif group == "행 이동" and self.body_subkind_var.get() == "아이템 상태":
                self.body_fourth_label.grid(row=0, column=6, sticky="w")
                self.body_fourth_label.configure(text="4차:")
                self.body_fourth_combo.configure(
                    textvariable=self.body_item_var,
                    values=tuple(self._body_target_display(item_id, name) for item_id, name in self.item_targets),
                )
                self.body_fourth_combo.grid(row=0, column=7, sticky="w", padx=(5, 10))
                if not self.body_item_var.get() and self.item_targets:
                    self._set_body_item(self.item_targets[0][0])
            elif group == "행 이동" and self.body_subkind_var.get() == "발견물":
                self.body_fourth_label.grid(row=0, column=6, sticky="w")
                self.body_fourth_label.configure(text="4차:")
                self.body_fourth_combo.configure(
                    textvariable=self.body_character_var,
                    values=tuple(
                        self._body_target_display(discovery_id, name)
                        for discovery_id, name in self.discovery_targets
                    ),
                    state="readonly",
                )
                self.body_fourth_combo.grid(row=0, column=7, sticky="w", padx=(5, 10))
                if not self.body_character_var.get() and self.discovery_targets:
                    self._set_body_character(self.discovery_targets[0][0])
            elif group == "행 이동" and self.body_subkind_var.get() == "NPC 조건":
                is_sponsor = self.body_detail_var.get() == "후원자"
                targets = self.sponsor_targets if is_sponsor else self.character_targets
                self.body_fourth_label.grid(row=0, column=6, sticky="w")
                self.body_fourth_label.configure(text="4차:")
                self.body_fourth_combo.configure(
                    textvariable=self.body_character_var,
                    values=tuple(self._body_target_display(target_id, name) for target_id, name in targets),
                )
                self.body_fourth_combo.grid(row=0, column=7, sticky="w", padx=(5, 10))
        elif kind in DIALOGUE_KINDS:
            self.body_detail_label.configure(text="화자:")
            self.body_detail_label.grid(row=0, column=4, sticky="w")
            self.body_speaker_combo.configure(state="readonly")
            self.body_speaker_combo.grid(row=0, column=5, sticky="w", padx=(5, 10))

        row = self.body_input_row

        def label(column: int, text: str) -> None:
            ttk.Label(row, text=text).grid(row=0, column=column, sticky="e")

        def entry(column: int, variable: tk.StringVar, span: int = 1) -> None:
            text_entry = kind in DIALOGUE_KINDS or kind == "발견물 이름 설정"
            NativeEdit(
                row,
                variable,
                width=170 if span == 1 else 360,
                numeric=not text_entry,
                allow_negative=kind == "상태값 증감",
            ).grid(
                row=0, column=column, columnspan=span, sticky="ew", padx=(5, 10 if span == 1 else 0),
            )

        def combo(column: int, textvariable: tk.StringVar, values: tuple[str, ...], span: int = 1, maximum: int | None = None) -> None:
            widget = ttk.Combobox(row, textvariable=textvariable, values=values, state="readonly")
            widget.grid(row=0, column=column, columnspan=span, sticky="ew", padx=(5, 10 if span == 1 else 0))
            widget.bind("<Up>", self._cycle_combobox)
            widget.bind("<Down>", self._cycle_combobox)
            self._autosize_combobox(widget, maximum=maximum)

        # 1~3차 분류가 실제 명령으로 확정되기 전에는 입력 컨트롤을 만들지 않는다.
        # 이 규칙 때문에 이전 명령의 값/체크박스가 다음 명령 화면에 남지 않는다.
        if kind not in BODY_COMMAND_KINDS:
            return

        no_input = {"음원 정지", "이미지 표시 종료", "대화창 숨김", "대화창 표시", "결과 거짓 설정", "결과 참 설정", "주인공 성격 판정"}
        if kind in no_input:
            return
        if kind == "특수 수치 판정":
            label(0, "판정값:")
            entry(1, self.special_check_value_var)
            label(2, "난이도:")
            entry(3, self.special_difficulty_var)
            return
        if kind in DIALOGUE_KINDS:
            label(0, "대사:")
            entry(1, self.body_value_var, 5)
            if kind == "대상 지정 대사":
                label(6, "대상 인물:")
                combo(7, self.body_character_var, tuple(
                    self._body_target_display(character_id, name)
                    for character_id, name in self.character_targets
                ), 2)
            return
        if kind == "발견물 이름 설정":
            label(0, "대상 발견물:")
            combo(1, self.body_character_var, tuple(self._body_target_display(discovery_id, name) for discovery_id, name in self.discovery_targets), 2)
            label(3, "이름:")
            entry(4, self.body_value_var)
            return
        if kind in CHARACTER_TARGET_COMMAND_KINDS:
            label(0, "인물:")
            combo(1, self.body_character_var, tuple(
                self._body_target_display(character_id, name)
                for character_id, name in self.character_targets
            ), 3)
            if kind == "인물 상태 비트 해제":
                label(4, "비트 번호:")
                entry(5, self.body_value_var)
            return
        if kind in ("아이템 획득", "아이템 상실", "이벤트 아이템 등록", "이벤트 아이템 처리"):
            label(0, "아이템:")
            combo(1, self.body_item_var, tuple(self._body_target_display(item_id, name) for item_id, name in self.item_targets), 3, maximum=16)
            return
        if kind == "신도시 생성":
            label(0, "도시:")
            combo(1, self.body_city_var, tuple(self._body_target_display(city_id, name) for city_id, name in self.city_targets), 3)
            return
        if kind == "발견물 등록/발견 처리":
            label(0, "발견물:")
            combo(1, self.body_character_var, tuple(self._body_target_display(discovery_id, name) for discovery_id, name in self.discovery_targets), 3)
            return
        if kind == "힌트 획득":
            label(0, "힌트:")
            combo(1, self.body_hint_var, tuple(self._body_target_display(hint_id, name) for hint_id, name in self.hint_targets if hint_id >= 0), 3)
            return
        if kind == "이벤트 결과 코드":
            label(0, "처리:")
            combo(1, self.body_result_var, tuple(name for _code, name in EVENT_RESULT_CODES), 2)
            return
        if kind in STAT_COMMAND_KINDS:
            label(0, "수치:")
            entry(1, self.body_value_var)
            ttk.Checkbutton(row, text="랜덤 범위:", variable=self.body_random_var, command=self._body_random_changed).grid(row=0, column=2, sticky="w")
            if self.body_random_var.get():
                entry(3, self.body_value2_var)
            return
        if kind in STAT_REFERENCE_COMMAND_KINDS:
            label(0, "참조 상태값 ID:")
            entry(1, self.body_value_var)
            return
        if kind == "날짜 경과":
            label(0, "일수:")
            entry(1, self.body_value_var)
            ttk.Checkbutton(row, text="랜덤 범위:", variable=self.body_random_var, command=self._body_random_changed).grid(row=0, column=2, sticky="w")
            if self.body_random_var.get():
                entry(3, self.body_value2_var)
            return
        if kind == "소지금 비교 분기":
            label(0, "소지금 기준값:")
            entry(1, self.body_value2_var)
            label(2, "이동할 행:")
            entry(3, self.body_value_var)
            return
        if kind == RUNTIME_REFERENCE_BRANCH_KIND:
            label(0, "기준값:")
            entry(1, self.body_value2_var)
            label(2, "특수 참조 ID:")
            entry(3, self.body_range_end_var)
            label(4, "이동할 행:")
            entry(5, self.body_value_var)
            return
        if kind in ("STORY0.CDS 외 분기", "STORY1.CDS 외 분기"):
            label(0, "외부 분기값:")
            entry(1, self.body_value_var)
            return
        if kind in NUMERIC_COMPARE_BRANCH_KINDS:
            label(0, "기준값:")
            entry(1, self.body_value2_var)
            label(2, "이동할 행:")
            entry(3, self.body_value_var)
            return
        if kind in (ITEM_POSSESSION_BRANCH_KIND, ITEM_ABSENCE_BRANCH_KIND):
            label(0, "이동할 행:")
            entry(1, self.body_value_var)
            return
        if kind == STATE_REFERENCE_COMPARE_BRANCH_KIND:
            label(0, "대상 상태값:")
            combo(1, self.body_stat_target_var, tuple(name for _stat_id, name in STAT_TARGETS))
            label(2, "참조 상태값 ID:")
            entry(3, self.body_value2_var)
            label(4, "이동할 행:")
            entry(5, self.body_value_var)
            return
        if kind == HINT_BRANCH_KIND:
            label(0, "이동할 행:")
            entry(1, self.body_value_var)
            return
        if kind == DISCOVERY_BRANCH_KIND:
            label(0, "이동할 행:")
            entry(1, self.body_value_var)
            return
        if kind == DISCOVERY_REGISTRATION_BRANCH_KIND:
            label(0, "이동할 행:")
            entry(1, self.body_value_var)
            return
        if kind == YEAR_RANGE_BRANCH_KIND:
            label(0, "시작 연도:")
            entry(1, self.body_value2_var)
            label(2, "종료 연도:")
            entry(3, self.body_range_end_var)
            label(4, "이동할 행:")
            entry(5, self.body_value_var)
            return
        if kind == YEAR_BRANCH_KIND:
            label(0, "기준 연도:")
            entry(1, self.body_value2_var)
            label(2, "이동할 행:")
            entry(3, self.body_value_var)
            return
        if kind == YEAR_UPPER_BRANCH_KIND:
            label(0, "연도 상한:")
            entry(1, self.body_value2_var)
            label(2, "이동할 행:")
            entry(3, self.body_value_var)
            return
        if kind == CITY_BRANCH_KIND:
            label(0, "도시:")
            combo(1, self.body_city_var, tuple(
                self._body_target_display(city_id, name) for city_id, name in self.city_targets
            ), 2)
            label(3, "이동할 행:")
            entry(4, self.body_value_var)
            return
        if kind == NPC_BRANCH_KIND:
            label(0, "이동할 행:")
            entry(1, self.body_value_var)
            return
        if kind == CHOICE_BRANCH_KIND:
            label(0, "선택값:")
            entry(1, self.body_value2_var)
            label(2, "이동할 행:")
            entry(3, self.body_value_var)
            return
        if kind in ("결과 거짓 시 이동", "결과 참 시 이동", "이전 조건 참 시 이동", "특수 분기"):
            label(0, "이동할 행:")
            entry(1, self.body_value_var)
            return
        label(0, "값:")
        entry(1, self.body_value_var, 5)

    def _hide_disabled_body_inputs(self) -> None:
        """Do not leave inapplicable command inputs as greyed-out placeholders."""
        if self.body_value_entry.grid_info() and str(self.body_value_entry.cget("state")) == "disabled":
            self.body_value_label.grid_remove()
            self.body_value_entry.grid_remove()
        if self.body_value2_entry.grid_info() and str(self.body_value2_entry.cget("state")) == "disabled":
            self.body_value2_entry.grid_remove()

    def _arrange_body_editor_rows(self, kind: str) -> None:
        """Use row 1 for classification and row 2 for its target/value controls."""
        editor = self.body_value_entry.master
        self.body_action_row.grid_configure(row=2)
        for column in range(11):
            editor.columnconfigure(column, weight=0)
        for column in (1, 3, 5):
            editor.columnconfigure(column, weight=1)

        is_dialogue = kind in DIALOGUE_KINDS
        is_character_dialogue = kind == "발견물 이름 설정"
        is_choice_branch = kind == CHOICE_BRANCH_KIND
        is_special_value_check = kind == "특수 수치 판정"
        is_date_passage = kind == "날짜 경과"
        is_item = kind in ("아이템 획득", "아이템 상실", "이벤트 아이템 등록", "이벤트 아이템 처리")
        is_city = kind == "신도시 생성"
        is_discovery_registration = kind == "발견물 등록/발견 처리"
        is_discovery_branch = kind == DISCOVERY_BRANCH_KIND
        is_hint_branch = kind == HINT_BRANCH_KIND
        is_hint_grant = kind == "힌트 획득"
        is_event_result = kind == "이벤트 결과 코드"

        # 상태값 명령은 1행에서 증감/설정을 고르고, 2행에서 대상·수치·랜덤 범위를 지정한다.
        if kind in STAT_COMMAND_KINDS:
            self.body_stat_target_label.grid(row=1, column=0, sticky="e")
            self.body_stat_target_combo.grid(row=1, column=1, sticky="ew", padx=(5, 10))
            self.body_value_label.grid(row=1, column=2, sticky="e")
            self.body_value_entry.grid(row=1, column=3, sticky="ew", padx=(5, 10))
            self.body_value2_label.grid(row=1, column=4, sticky="w")
            self.body_value2_entry.grid(row=1, column=5, sticky="ew", padx=(5, 0))
            return

        if kind in NUMERIC_COMPARE_BRANCH_KINDS:
            self.body_stat_target_label.grid(row=1, column=0, sticky="e")
            self.body_stat_target_combo.grid(row=1, column=1, sticky="ew", padx=(5, 10))
            self.body_value2_plain_label.grid(row=1, column=2, sticky="e")
            self.body_value2_entry.grid(row=1, column=3, sticky="ew", padx=(5, 10))
            self.body_value2_label.grid(row=1, column=4, sticky="w")
            self.body_value_label.grid(row=1, column=6, sticky="e")
            self.body_value_entry.grid(row=1, column=7, sticky="ew", padx=(5, 0))
            return

        if is_dialogue:
            # 화자는 분류행의 3차 선택으로 두고, 2행에는 대사 입력만 둔다.
            self.body_value_label.grid(row=1, column=0, sticky="e")
            self.body_value_entry.grid(row=1, column=1, columnspan=5, sticky="ew", padx=(5, 0))
            return

        if is_character_dialogue:
            self.body_character_label.grid(row=1, column=0, sticky="e")
            self.body_character_entry.grid(row=1, column=1, sticky="ew", padx=(5, 10))
            self.body_value_label.grid(row=1, column=2, sticky="e")
            self.body_value_entry.grid(row=1, column=3, sticky="ew", padx=(5, 0))
            return

        if is_item:
            self.body_value_label.grid(row=1, column=0, sticky="e")
            self.body_item_combo.grid(row=1, column=1, columnspan=3, sticky="ew", padx=(5, 0))
            return
        if is_city:
            self.body_value_label.grid(row=1, column=0, sticky="e")
            self.body_city_combo.grid(row=1, column=1, columnspan=3, sticky="ew", padx=(5, 0))
            return
        if is_discovery_registration:
            self.body_value_label.grid(row=1, column=0, sticky="e")
            self.body_character_combo.grid(row=1, column=1, columnspan=3, sticky="ew", padx=(5, 0))
            return
        if is_event_result:
            self.body_value_label.grid(row=1, column=0, sticky="e")
            self.body_result_combo.grid(row=1, column=1, sticky="ew", padx=(5, 0))
            return
        if is_hint_grant:
            self.body_hint_label.grid(row=1, column=0, sticky="e")
            self.body_hint_combo.grid(row=1, column=1, columnspan=3, sticky="ew", padx=(5, 0))
            return
        if is_hint_branch:
            self.body_hint_state_label.grid(row=1, column=0, sticky="e")
            self.body_hint_state_combo.grid(row=1, column=1, sticky="ew", padx=(5, 10))
            self.body_hint_label.grid(row=1, column=2, sticky="e")
            self.body_hint_combo.grid(row=1, column=3, sticky="ew", padx=(5, 10))
            self.body_value_label.grid(row=1, column=4, sticky="e")
            self.body_value_entry.grid(row=1, column=5, sticky="ew", padx=(5, 0))
            return
        if is_discovery_branch:
            self.body_character_label.grid(row=1, column=0, sticky="e")
            self.body_character_combo.grid(row=1, column=1, sticky="ew", padx=(5, 10))
            self.body_value_label.grid(row=1, column=2, sticky="e")
            self.body_value_entry.grid(row=1, column=3, sticky="ew", padx=(5, 0))
            return
        if is_choice_branch:
            self.body_value2_plain_label.grid(row=1, column=0, sticky="e")
            self.body_value2_entry.grid(row=1, column=1, sticky="ew", padx=(5, 10))
            self.body_value_label.grid(row=1, column=2, sticky="e")
            self.body_value_entry.grid(row=1, column=3, sticky="ew", padx=(5, 0))
            return
        if is_special_value_check:
            # 공용 값 컨트롤과 분리한 전용 입력칸을 사용한다.
            self.body_value_label.grid_remove()
            self.body_value_entry.grid_remove()
            self.body_value2_plain_label.grid_remove()
            self.body_value2_entry.grid_remove()
            self.special_check_value_label.grid(row=1, column=0, sticky="e")
            self.special_check_value_entry.grid(row=1, column=1, sticky="ew", padx=(5, 16))
            self.special_difficulty_label.grid(row=1, column=2, sticky="e")
            self.special_difficulty_entry.grid(row=1, column=3, sticky="ew", padx=(5, 0))
            self.special_check_value_entry.configure(state="normal")
            self.special_difficulty_entry.configure(state="normal")
            return
        if is_date_passage:
            self.body_value_label.grid(row=1, column=0, sticky="e")
            # 일수 입력칸과 랜덤 범위 체크박스가 맞닿지 않도록 간격을 둔다.
            self.body_value_entry.grid(row=1, column=1, sticky="ew", padx=(5, 20))
            self.body_value2_label.grid(row=1, column=2, sticky="w", padx=(0, 10))
            self.body_value2_entry.grid(row=1, column=3, sticky="ew", padx=(5, 0))
            return

        # 값 입력이 필요한 나머지 명령(미디어·이동 등)은 2행에 넓게 배치한다.
        if self.body_value_entry.grid_info():
            self.body_value_label.grid(row=1, column=0, sticky="e")
            self.body_value_entry.grid(row=1, column=1, columnspan=5, sticky="ew", padx=(5, 0))

    def _builder_body_kind(self) -> str:
        group = self.body_command_var.get()
        if group == "미디어":
            return MEDIA_DETAIL_TO_KIND.get(
                (self.body_subkind_var.get(), self.body_detail_var.get()),
                "DSTILL 이미지 표시",
            )
        if group == "행 이동":
            detail_kind = MOVE_DETAIL_TO_KIND.get((self.body_subkind_var.get(), self.body_detail_var.get()))
            if detail_kind is not None:
                return detail_kind
            return BODY_GROUP_TO_KIND.get((group, self.body_subkind_var.get()), "특수 분기")
        if group == "상태값":
            subkind = self.body_subkind_var.get()
            if subkind == "증감":
                return "상태값 증감"
            if subkind == "설정":
                return "상태값 설정"
            if subkind == "증감 (상태값 참조)":
                return "상태값 참조 증가"
            if self.body_random_var.get():
                return STATE_LESS_RANDOM_BRANCH_KIND if subkind == "미만" else STATE_LESS_OR_EQUAL_RANDOM_BRANCH_KIND
            return STATE_LESS_BRANCH_KIND if subkind == "미만" else STATE_LESS_OR_EQUAL_BRANCH_KIND
        return BODY_GROUP_TO_KIND.get((group, self.body_subkind_var.get()), BODY_GROUP_TO_KIND.get((group, ""), group))
        self.body_value2_entry.configure(
            state="normal" if is_state_compare_branch or (is_random_range and self.body_random_var.get()) else "disabled"
        )
        if kind == "이벤트 결과 코드" and not self.body_value_var.get().strip():
            self.body_value_var.set("0")
        if is_dialogue:
            self.body_speaker_label.grid(row=0, column=2, sticky="e")
            self.body_speaker_combo.grid(row=0, column=3, sticky="ew", padx=(5, 14))
            if not self.body_speaker_var.get():
                self.body_speaker_var.set("화자 없음")
        else:
            self.body_speaker_label.grid_remove()
            self.body_speaker_combo.grid_remove()
        if is_character_dialogue:
            self.body_character_label.grid(row=0, column=2, sticky="e")
            self.body_character_combo.grid_remove()
            self.body_character_entry.grid(row=0, column=3, sticky="ew", padx=(5, 14))
            if not self.body_character_var.get() and self.discovery_targets:
                self._set_body_character(self.discovery_targets[0][0])
        elif is_discovery_registration:
            self.body_character_label.grid_remove()
            self.body_character_entry.grid_remove()
        elif not is_discovery_branch:
            self.body_character_label.grid_remove()
            self.body_character_combo.grid_remove()
            self.body_character_entry.grid_remove()
        if is_stat or is_state_compare_branch:
            self.body_stat_target_label.grid()
            self.body_stat_target_combo.grid()
            # 새 명령 종류로 상태값을 고르면, 직전 명령에서 비활성화된
            # 대상 콤보도 함께 다시 선택 가능 상태로 돌린다.
            self.body_stat_target_combo.configure(state="readonly")
            if not self.body_stat_target_var.get():
                self._set_body_stat_target(STAT_TARGETS[0][0])
        else:
            self.body_stat_target_label.grid_remove()
            self.body_stat_target_combo.grid_remove()
            self.body_stat_target_combo.configure(state="disabled")
        if is_hint_branch:
            self.body_hint_state_combo.configure(state="readonly")
            self.body_hint_combo.configure(state="readonly")
        else:
            self.body_hint_state_combo.grid_remove()
            self.body_hint_combo.grid_remove()
            self.body_hint_state_combo.configure(state="disabled")
            self.body_hint_combo.configure(state="disabled")

    def _set_body_speaker(self, speaker_prefix: bytes) -> None:
        for name, prefix in self.dialogue_speakers.items():
            if prefix == speaker_prefix:
                self.body_speaker_var.set(name)
                return
        # 알려지지 않은 태그도 수정 전에는 손실되지 않도록 임시 항목으로 남긴다.
        unknown = "기존 화자 (알 수 없음)"
        values = list(self.body_speaker_combo.cget("values"))
        if unknown not in values:
            values.append(unknown)
            self.body_speaker_combo.configure(values=tuple(values))
            self._autosize_combobox(self.body_speaker_combo)
        self.body_speaker_var.set(unknown)

    def _body_speaker_prefix(self) -> bytes:
        selected = self.body_speaker_var.get()
        if selected in self.dialogue_speakers:
            return self.dialogue_speakers[selected]
        if selected == "기존 화자 (알 수 없음)" and self.selected_body_index is not None:
            return bytes(self.body_tokens[self.selected_body_index].get("speaker_prefix", b""))
        raise ValueError("목록에 있는 화자를 선택하세요.")

    def _set_body_character(self, character_id: int) -> None:
        for discovery_id, name in self.discovery_targets:
            if discovery_id == character_id:
                self.body_character_var.set(self._body_target_display(discovery_id, name))
                return
        self.body_character_var.set(str(character_id))

    @staticmethod
    def _body_target_display(target_id: int, name: str) -> str:
        """Keep command target comboboxes consistent with condition target notation."""
        return f"{target_id:03d} | {name}"

    @staticmethod
    def _body_target_id_from_text(text: str, targets: list[tuple[int, str]], error_message: str) -> int:
        """Resolve an `ID | name` combobox item without relying on duplicate names."""
        try:
            target_id = int(text.split("|", 1)[0].strip())
        except ValueError as exc:
            raise ValueError(error_message) from exc
        if any(candidate_id == target_id for candidate_id, _name in targets):
            return target_id
        raise ValueError(error_message)

    def _body_character_id(self) -> int:
        text = self.body_character_var.get().strip()
        if not text:
            raise ValueError("발견물을 선택하세요. EXE 연결이 필요합니다.")
        return self._body_target_id_from_text(
            text, self.discovery_targets, "목록에 있는 발견물을 선택하세요. EXE 연결이 필요합니다.",
        )

    def _set_body_npc(self, character_id: int, targets: list[tuple[int, str]] | None = None) -> None:
        targets = self.character_targets if targets is None else targets
        for candidate_id, name in targets:
            if candidate_id == character_id:
                self.body_character_var.set(self._body_target_display(candidate_id, name))
                return
        self.body_character_var.set(str(character_id))

    def _body_npc_id(self, targets: list[tuple[int, str]] | None = None) -> int:
        targets = self.character_targets if targets is None else targets
        return self._body_target_id_from_text(
            self.body_character_var.get().strip(), targets,
            "목록에 있는 NPC를 선택하세요.",
        )

    def _set_body_item(self, item_id: int) -> None:
        for candidate_id, name in self.item_targets:
            if candidate_id == item_id:
                self.body_item_var.set(self._body_target_display(candidate_id, name))
                return
        self.body_item_var.set(str(item_id))

    def _body_item_id(self) -> int:
        text = self.body_item_var.get().strip()
        return self._body_target_id_from_text(text, self.item_targets, "목록에 있는 아이템만 선택할 수 있습니다.")

    def _set_body_city(self, city_id: int) -> None:
        for candidate_id, name in self.city_targets:
            if candidate_id == city_id:
                self.body_city_var.set(self._body_target_display(candidate_id, name))
                return
        self.body_city_var.set(str(city_id))

    def _body_city_id(self) -> int:
        text = self.body_city_var.get().strip()
        return self._body_target_id_from_text(text, self.city_targets, "목록에 있는 도시를 선택하세요.")

    def _body_input_value(self, kind: str) -> str:
        """Return the appropriate editor value for the selected body command."""
        if kind == "특수 수치 판정":
            return self.special_check_value_var.get().strip()
        if kind == "음원 정지":
            # 새 정지 명령에는 별도 지정값이 필요 없도록 0을 기본값으로 쓴다.
            return "0"
        if kind in ("아이템 획득", "아이템 상실", "이벤트 아이템 등록", "이벤트 아이템 처리"):
            return str(self._body_item_id())
        if kind == "신도시 생성":
            return str(self._body_city_id())
        if kind == "발견물 등록/발견 처리":
            return str(self._body_character_id())
        if kind in RANDOM_RANGE_COMMAND_KINDS:
            first = self.body_value_var.get().strip()
            second = self.body_value2_var.get().strip()
            return f"{first}~{second}" if self.body_random_var.get() else first
        if kind == "이벤트 결과 코드":
            return str(self._body_result_code())
        return self.body_value_var.get()

    def _set_body_result(self, code: int) -> None:
        self.body_result_var.set(EVENT_RESULT_NAMES.get(code, f"알 수 없는 결과 ({code})"))

    def _body_result_code(self) -> int:
        selected = self.body_result_var.get()
        for code, name in EVENT_RESULT_CODES:
            if selected == name:
                return code
        raise ValueError("목록에서 이벤트 처리 결과를 선택하세요.")

    def _body_random_changed(self) -> None:
        """랜덤 범위를 지원하는 명령에서만 두 번째 값을 편집하게 한다."""
        if self._builder_body_kind() not in RANDOM_RANGE_COMMAND_KINDS:
            return
        self._body_kind_changed()

    def _set_body_stat_target(self, stat_id: int) -> None:
        """상태값 대상 콤보에 기존 원본의 번호도 손실 없이 표시한다."""
        name = STAT_TARGET_NAMES.get(stat_id, "미사용/미확인")
        if self.body_command_var.get() == "상태값":
            self.body_detail_var.set(name)
        item = name
        values = list(self.body_stat_target_combo.cget("values"))
        if item not in values:
            values.append(item)
            self.body_stat_target_combo.configure(values=tuple(values))
            self._autosize_combobox(self.body_stat_target_combo)
        self.body_stat_target_var.set(item)

    def _body_stat_id(self) -> int:
        text = (
            self.body_detail_var.get().strip()
            if self.body_command_var.get() == "상태값"
            else self.body_stat_target_var.get().strip()
        )
        for stat_id, name in STAT_TARGETS:
            if name == text:
                return stat_id
        raise ValueError("목록에서 상태값 대상을 선택하세요.")

    def _set_body_hint(self, hint_id: int) -> None:
        for candidate_id, name in self.hint_targets:
            if candidate_id == hint_id:
                self.body_hint_var.set(self._body_target_display(candidate_id, name))
                return
        self.body_hint_var.set(f"힌트 {hint_id}")

    def _body_hint_id(self) -> int:
        return self._body_target_id_from_text(
            self.body_hint_var.get().strip(), self.hint_targets, "목록에서 힌트를 선택하세요.",
        )

    @staticmethod
    def _new_body_token(
        kind: str,
        value: str = "",
        character_id: int | None = None,
        stat_id: int | None = None,
        compare_value: int | None = None,
        hint_id: int | None = None,
        hint_active: bool = True,
        dialogue_layout: str = "text_first",
        speaker_prefix: bytes = b"",
        choice_value: int | None = None,
        npc_type: int = 0x0D,
        item_id: int | None = None,
    ) -> dict[str, object]:
        if kind in DIALOGUE_KINDS:
            encoded = (
                encode_multichoice_dialogue_text(value)
                if kind == "다중 선택지 대사"
                else encode_dialogue_text(value)
            )
            if b"\0" in encoded:
                raise ValueError("대사에는 NUL 문자를 넣을 수 없습니다.")
            if kind == "대상 지정 대사":
                if character_id is None or not 0 <= character_id <= 0xFFFF:
                    raise ValueError("목록에서 대상 인물을 선택하세요.")
                return {
                    "kind": kind,
                    "raw": b"\x20\x0A" + speaker_prefix + encoded + b"\0\x08" + struct.pack("<H", character_id),
                    "value": value, "character_id": character_id, "speaker_prefix": speaker_prefix,
                    "editable": True, "flag": 0x20,
                }
            # 일반 대사는 00 0A로 시작한다. 00 창 플래그가 없으면 분기 직후의
            # 대사를 게임이 본문 명령으로 처리하지 못하는 경우가 있다.
            flag = b"\x0B" if kind == "예/아니오 대사" else b"\x10" if kind == "다중 선택지 대사" else b"\x00"
            suffix = b"\0\0" if kind == "다중 선택지 대사" else b"\0"
            return {
                "kind": kind,
                "raw": flag + b"\x0A" + speaker_prefix + encoded + suffix,
                "value": value,
                "speaker_prefix": speaker_prefix,
                "editable": True,
                "flag": 0x0B if kind == "예/아니오 대사" else 0x10 if kind == "다중 선택지 대사" else None,
            }
        if kind == "특수 조우 연출 설정":
            numeric_value = int(str(value).strip())
            if not 0 <= numeric_value <= 65535:
                raise ValueError("특수 조우 연출 값은 0~65,535 범위여야 합니다.")
            return {
                "kind": kind,
                "raw": b"\x00\x1E" + struct.pack("<H", numeric_value),
                "value": numeric_value,
                "editable": True,
            }
        if kind == "해상 전투":
            numeric_value = int(str(value).strip())
            if not 0 <= numeric_value <= 65535:
                raise ValueError("해상 전투 상대 ID는 0~65,535 범위여야 합니다.")
            return {
                "kind": kind,
                "raw": b"\x0D\x0D" + struct.pack("<H", numeric_value),
                "value": numeric_value,
                "editable": True,
            }
        if kind in ("인물 이벤트 실행", "인물 이벤트 실행 (보조)"):
            numeric_value = int(str(value).strip())
            if not 0 <= numeric_value <= 65535:
                raise ValueError("인물 이벤트 ID는 0~65,535 범위여야 합니다.")
            opcode = 0x0C if kind == "인물 이벤트 실행" else 0x2F
            return {
                "kind": kind,
                "raw": bytes((opcode, 0x0D)) + struct.pack("<H", numeric_value),
                "value": numeric_value,
                "editable": True,
            }
        if kind in CHARACTER_TARGET_COMMAND_KINDS:
            if character_id is None or not 0 <= character_id <= 0xFFFF:
                raise ValueError("목록에서 인물을 선택하세요.")
            raw_prefix = {
                "인물 참조 설정": b"\x26\x1C\x1A\0\x08",
                "인물 상태 처리 1": b"\x38\x0D",
                "인물 상태 처리 2": b"\x3D\x0D",
                "인물 상태 처리 3": b"\x23\x08",
                "인물 상태 처리 4": b"\x22\x08",
                "인물 상태 비트 해제": b"\x22\x10",
                "인물 선택 판정": b"\x2F\x08",
                "인물 위치 판정": b"\x3C\x08",
            }[kind]
            if kind == "인물 상태 비트 해제":
                bit_index = int(str(value).strip())
                if not 0 <= bit_index <= 15:
                    raise ValueError("해제할 비트 번호는 0~15 범위여야 합니다.")
                raw_prefix += struct.pack("<H", bit_index) + b"\x08"
            return {
                "kind": kind, "raw": raw_prefix + struct.pack("<H", character_id),
                "value": character_id, "character_id": character_id, "editable": True,
            }
        if kind == "이벤트 내부 참조":
            numeric_value = int(str(value).strip())
            if not 0 <= numeric_value <= 65535:
                raise ValueError("내부 이벤트 참조값은 0~65,535 범위여야 합니다.")
            return {
                "kind": kind,
                "raw": b"\x30\x1D" + struct.pack("<H", numeric_value),
                "value": numeric_value,
                "editable": True,
            }
        if kind == "주인공 성격 판정":
            return {"kind": kind, "raw": b"\x31", "value": None, "editable": True}
        if kind == "이벤트 분류 설정":
            numeric_value = int(str(value).strip())
            if not 0 <= numeric_value <= 65535:
                raise ValueError("이벤트 분류 값은 0~65,535 범위여야 합니다.")
            return {
                "kind": kind,
                "raw": b"\x26\x0F" + struct.pack("<H", numeric_value),
                "value": numeric_value,
                "editable": True,
            }
        if kind == "이벤트 조건 판정":
            numeric_value = int(str(value).strip())
            if not 0 <= numeric_value <= 65535:
                raise ValueError("이벤트 조건 값은 0~65,535 범위여야 합니다.")
            return {
                "kind": kind,
                "raw": b"\x35\x1C" + struct.pack("<H", numeric_value),
                "value": numeric_value,
                "editable": True,
            }
        if kind == "발견물 이름 설정":
            if character_id is None or not 0 <= character_id <= 65535:
                raise ValueError("발견물 ID가 올바르지 않습니다.")
            encoded = value.encode("cp949")
            if b"\0" in encoded:
                raise ValueError("대사에는 NUL 문자를 넣을 수 없습니다.")
            packed_id = struct.pack("<H", character_id)
            content = speaker_prefix + encoded
            if dialogue_layout == "id_first":
                raw = b"\x1F\x0B" + packed_id + b"\x0A" + content + b"\0"
            else:
                raw = b"\x1F\x0A" + content + b"\0\x0B" + packed_id
                dialogue_layout = "text_first"
            return {
                "kind": kind,
                "raw": raw,
                "value": value,
                "character_id": character_id,
                "dialogue_layout": dialogue_layout,
                "speaker_prefix": speaker_prefix,
                "editable": True,
            }
        if kind == "신도시 생성":
            city_id = int(str(value).strip())
            if not 0 <= city_id <= 65535:
                raise ValueError("도시 ID는 0~65,535 범위여야 합니다.")
            return {
                "kind": kind,
                "raw": b"\x26\x08" + struct.pack("<H", city_id),
                "value": city_id,
                "editable": True,
            }
        if kind in ("결과 거짓 시 이동", "결과 참 시 이동", "이전 조건 참 시 이동", "특수 분기"):
            target_index = int(str(value).strip())
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            opcode = {
                "결과 거짓 시 이동": 0x45,
                "결과 참 시 이동": 0x47,
                "이전 조건 참 시 이동": 0x4B,
                "특수 분기": 0x56,
            }[kind]
            return {
                "kind": kind,
                "raw": b"\x43" + bytes((opcode,)) + b"\0\0",
                "value": target_index,
                "branch_opcode": opcode,
                "target_index": target_index,
                "editable": True,
            }
        if kind == "특수 수치 판정":
            try:
                check_value = int(str(value).strip())
                difficulty = int(str(compare_value).strip())
            except (TypeError, ValueError) as exc:
                raise ValueError("판정값과 난이도는 정수로 입력하세요.") from exc
            if not 0 <= check_value <= 0xFFFFFFFF or not 0 <= difficulty <= 0xFFFF:
                raise ValueError("판정값은 0~4,294,967,295, 난이도는 0~65,535 범위여야 합니다.")
            return {
                "kind": kind,
                "raw": b"\x0E\x14" + struct.pack("<I", check_value) + b"\x04" + struct.pack("<H", difficulty),
                "value": check_value, "difficulty": difficulty, "editable": True,
            }
        if kind == "이벤트 플래그 설정":
            flag_id = int(str(value).strip())
            if not 0 <= flag_id <= 0xFFFF:
                raise ValueError("이벤트 플래그 ID는 0~65,535 범위여야 합니다.")
            return {
                "kind": kind, "raw": b"\x01\x15" + struct.pack("<H", flag_id),
                "value": flag_id, "editable": True,
            }
        if kind == "내부 상태 설정":
            state_id = int(str(value).strip())
            if not 0 <= state_id <= 0xFFFF:
                raise ValueError("내부 상태 ID는 0~65,535 범위여야 합니다.")
            return {"kind": kind, "raw": b"\x22\x00" + struct.pack("<H", state_id), "value": state_id, "editable": True}
        if kind == "특수 상태 처리":
            numeric_value = int(str(value).strip())
            if not 0 <= numeric_value <= 0xFFFFFFFF:
                raise ValueError("특수 상태 값은 0~4,294,967,295 범위여야 합니다.")
            return {"kind": kind, "raw": b"\x34\x1C\x02\0\x1A" + struct.pack("<I", numeric_value), "value": numeric_value, "editable": True}
        if kind == CHOICE_BRANCH_KIND:
            target_index = int(str(value).strip())
            if choice_value is None or not 0 <= choice_value <= 255:
                raise ValueError("선택값은 0~255 범위여야 합니다.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            prefix = b"\x43\x11\x0A" + bytes((choice_value,))
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "choice_value": choice_value, "branch_prefix": prefix,
                "target_index": target_index, "editable": True,
            }
        if kind == YEAR_RANGE_BRANCH_KIND:
            target_index = int(str(value).strip())
            try:
                start_text, end_text = (part.strip() for part in str(compare_value).split("~", 1))
                start_year, end_year = int(start_text), int(end_text)
            except (AttributeError, ValueError) as exc:
                raise ValueError("연도 범위는 예: 1487~1488 형식으로 입력하세요.") from exc
            if not 0 <= start_year <= end_year <= 65535 or not 1 <= target_index <= 65535:
                raise ValueError("연도 범위 또는 이동할 행이 올바르지 않습니다.")
            prefix = b"\x43\x36\x16" + struct.pack("<H", start_year) + b"\x16" + struct.pack("<H", end_year)
            return {"kind": kind, "raw": prefix + b"\0\0", "value": target_index, "start_year": start_year, "end_year": end_year, "branch_prefix": prefix, "target_index": target_index, "editable": True}
        if kind == YEAR_BRANCH_KIND:
            target_index = int(str(value).strip())
            year = int(str(compare_value).strip())
            if not 0 <= year <= 65535 or not 1 <= target_index <= 65535:
                raise ValueError("기준 연도 또는 이동할 행이 올바르지 않습니다.")
            prefix = b"\x43\x1B\x16" + struct.pack("<H", year)
            return {"kind": kind, "raw": prefix + b"\0\0", "value": target_index, "year": year, "branch_prefix": prefix, "target_index": target_index, "editable": True}
        if kind == YEAR_UPPER_BRANCH_KIND:
            target_index = int(str(value).strip())
            year = int(str(compare_value).strip())
            if not 0 <= year <= 65535 or not 1 <= target_index <= 65535:
                raise ValueError("연도 상한 또는 이동할 행이 올바르지 않습니다.")
            prefix = b"\x43\x39\x16" + struct.pack("<H", year)
            return {"kind": kind, "raw": prefix + b"\0\0", "value": target_index, "year": year, "branch_prefix": prefix, "target_index": target_index, "editable": True}
        if kind == "힌트 획득":
            if hint_id is None or not 0 <= hint_id <= 65535:
                raise ValueError("목록에서 힌트를 선택하세요.")
            return {"kind": kind, "raw": b"\x05\x0E" + struct.pack("<H", hint_id), "value": hint_id, "editable": True}
        if kind == HINT_BRANCH_KIND:
            target_index = int(str(value).strip())
            if hint_id is None or not 0 <= hint_id <= 65535:
                raise ValueError("목록에서 힌트를 선택하세요.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            prefix = b"\x43" + (b"\x0F" if hint_active else b"\x12") + b"\x0E" + struct.pack("<H", hint_id)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "hint_id": hint_id, "hint_active": hint_active, "branch_prefix": prefix,
                "target_index": target_index, "editable": True,
            }
        if kind in (ITEM_POSSESSION_BRANCH_KIND, ITEM_ABSENCE_BRANCH_KIND):
            target_index = int(str(value).strip())
            if item_id is None or not 0 <= item_id <= 0xFFFF:
                raise ValueError("목록에서 아이템을 선택하세요.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            prefix = b"\x43" + (b"\x12" if kind == ITEM_POSSESSION_BRANCH_KIND else b"\x0F") + b"\x05" + struct.pack("<H", item_id)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "item_id": item_id, "branch_prefix": prefix, "target_index": target_index,
                "editable": True,
            }
        if kind == "이미지 표시 종료":
            return {"kind": kind, "raw": b"\x33", "value": None, "editable": True}
        if kind == "대화창 숨김":
            return {"kind": kind, "raw": b"\x48", "value": None, "editable": True}
        if kind == "대화창 표시":
            return {"kind": kind, "raw": b"\x49", "value": None, "editable": True}
        if kind == "결과 거짓 설정":
            return {"kind": kind, "raw": b"\x46", "value": None, "editable": True}
        if kind == "결과 참 설정":
            return {"kind": kind, "raw": b"\x4A", "value": None, "editable": True}
        if kind == "이벤트 결과 코드":
            text = str(value).strip()
            try:
                code = int(text)
            except ValueError:
                code = next((candidate for candidate, name in EVENT_RESULT_CODES if name == text), -1)
            if not 0 <= code <= 2:
                raise ValueError("목록에서 이벤트 처리 결과를 선택하세요.")
            return {
                "kind": kind,
                "raw": bytes((0x4C + code,)),
                "value": code,
                "editable": True,
            }
        if kind == DISCOVERY_BRANCH_KIND:
            target_index = int(str(value).strip())
            if character_id is None or not 0 <= character_id <= 65535:
                raise ValueError("목록에서 대상 발견물을 선택하세요.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            prefix = b"\x43\x3A\x0B" + struct.pack("<H", character_id)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "character_id": character_id, "branch_prefix": prefix,
                "target_index": target_index, "editable": True,
            }
        if kind == DISCOVERY_REGISTRATION_BRANCH_KIND:
            target_index = int(str(value).strip())
            if character_id is None or not 0 <= character_id <= 65535:
                raise ValueError("목록에서 대상 발견물을 선택하세요.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            prefix = b"\x43\x02\x0B" + struct.pack("<H", character_id)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "character_id": character_id, "branch_prefix": prefix,
                "target_index": target_index, "editable": True,
            }
        if kind == NPC_BRANCH_KIND:
            target_index = int(str(value).strip())
            if character_id is None or not 0 <= character_id <= 0xFFFF:
                raise ValueError("목록에서 NPC를 선택하세요.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            if npc_type not in (0x0D, 0x12):
                raise ValueError("NPC 종류는 인물 또는 후원자여야 합니다.")
            prefix = b"\x43\x37" + bytes((npc_type,)) + struct.pack("<H", character_id)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "character_id": character_id, "npc_type": npc_type, "branch_prefix": prefix,
                "target_index": target_index, "editable": True,
            }
        if kind == CITY_BRANCH_KIND:
            target_index = int(str(value).strip())
            if character_id is None or not 0 <= character_id <= 0xFFFF:
                raise ValueError("목록에서 도시를 선택하세요.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            prefix = b"\x43\x17\x08" + struct.pack("<H", character_id)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "character_id": character_id, "branch_prefix": prefix,
                "target_index": target_index, "editable": True,
            }
        if kind == "소지금 비교 분기":
            target_index = int(str(value).strip())
            if compare_value is None or not 0 <= int(compare_value) <= 0xFFFFFFFF:
                raise ValueError("소지금 기준값은 0~4,294,967,295 범위여야 합니다.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            threshold = int(compare_value)
            prefix = b"\x43\x2C\x1C\x03\0\x1A" + struct.pack("<I", threshold)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "compare_value": threshold, "branch_prefix": prefix,
                "target_index": target_index, "editable": True,
            }
        if kind == RUNTIME_REFERENCE_BRANCH_KIND:
            target_index = int(str(value).strip())
            if compare_value is None or not 0 <= int(compare_value) <= 0xFFFF:
                raise ValueError("특수 참조 기준값은 0~65,535 범위여야 합니다.")
            if character_id is None or not 0 <= character_id <= 0xFFFF:
                raise ValueError("특수 참조 ID는 0~65,535 범위여야 합니다.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            prefix = b"\x43\x28\0" + struct.pack("<H", int(compare_value)) + b"\x08" + struct.pack("<H", character_id)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "threshold": int(compare_value), "runtime_id": character_id,
                "branch_prefix": prefix, "target_index": target_index, "editable": True,
            }
        if kind in ("STORY0.CDS 외 분기", "STORY1.CDS 외 분기"):
            external_offset = int(str(value).strip())
            if not 0 <= external_offset <= 0xFFFF:
                raise ValueError("외부 분기값은 0~65,535 범위여야 합니다.")
            opcode = 0x6D if kind.startswith("STORY0") else 0x6E
            return {"kind": kind, "raw": b"\x43" + bytes((opcode,)) + struct.pack("<H", external_offset), "value": external_offset, "editable": True}
        if kind in STATE_COMPARE_BRANCH_KINDS:
            target_index = int(str(value).strip())
            if stat_id not in STAT_TARGET_NAMES:
                raise ValueError("실행 파일에서 처리되는 상태값 대상을 선택하세요.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            if kind in RANDOM_STATE_COMPARE_BRANCH_KINDS:
                try:
                    first_text, last_text = (part.strip() for part in str(compare_value).split("~", 1))
                    first, last = int(first_text), int(last_text)
                except (ValueError, AttributeError) as exc:
                    raise ValueError("기준 범위는 예: 60~79 형식으로 입력하세요.") from exc
                if not 0 <= first <= last <= 0xFFFFFFFF:
                    raise ValueError("기준 범위는 0~4,294,967,295 범위여야 합니다.")
                opcode = {
                    STATE_GREATER_RANDOM_BRANCH_KIND: 0x2B,
                    STATE_LESS_RANDOM_BRANCH_KIND: 0x2C,
                    STATE_LESS_OR_EQUAL_RANDOM_BRANCH_KIND: 0x2D,
                }[kind]
                prefix = b"\x43" + bytes((opcode,)) + b"\x1C" + struct.pack("<H", stat_id) + b"\x20" + struct.pack("<I", last - first + 1) + struct.pack("<I", first)
                compare_value = first
                compare_value_text = f"{first}~{last}"
            else:
                if compare_value is None or not 0 <= int(compare_value) <= 0xFFFFFFFF:
                    raise ValueError("기준값은 0~4,294,967,295 범위여야 합니다.")
                comparison_opcode = {
                    STATE_GREATER_BRANCH_KIND: 0x2B,
                    STATE_LESS_BRANCH_KIND: 0x2C,
                    STATE_LESS_OR_EQUAL_BRANCH_KIND: 0x2D,
                }[kind]
                prefix = b"\x43" + bytes((comparison_opcode,)) + b"\x1C" + struct.pack("<H", stat_id) + b"\x14" + struct.pack("<I", int(compare_value))
                compare_value = int(compare_value)
                compare_value_text = None
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "stat_id": stat_id, "compare_value": compare_value, "compare_value_text": compare_value_text, "branch_prefix": prefix,
                "target_index": target_index, "editable": True,
            }
        if kind == ABILITY_COMPARE_BRANCH_KIND:
            target_index = int(str(value).strip())
            if stat_id not in STAT_TARGET_NAMES:
                raise ValueError("실행 파일에서 처리되는 상태값 대상을 선택하세요.")
            if compare_value is None or not 0 <= int(compare_value) <= 0xFFFFFFFF:
                raise ValueError("기준값은 0~4,294,967,295 범위여야 합니다.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            threshold = int(compare_value)
            prefix = b"\x43\x2D\x1C" + struct.pack("<H", stat_id) + b"\x1A" + struct.pack("<I", threshold)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "stat_id": stat_id, "compare_value": threshold,
                "branch_prefix": prefix, "target_index": target_index, "editable": True,
            }
        if kind in (ABILITY_COMPARE3_BRANCH_KIND, STATE_SCALAR_COMPARE_BRANCH_KIND):
            target_index = int(str(value).strip())
            if stat_id not in STAT_TARGET_NAMES:
                raise ValueError("실행 파일에서 처리되는 상태값 대상을 선택하세요.")
            if compare_value is None or not 0 <= int(compare_value) <= 0xFFFFFFFF:
                raise ValueError("기준값은 0~4,294,967,295 범위여야 합니다.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            threshold = int(compare_value)
            opcode = 0x2B if kind == ABILITY_COMPARE3_BRANCH_KIND else 0x2E
            prefix = b"\x43" + bytes((opcode,)) + b"\x1C" + struct.pack("<H", stat_id) + b"\x1A" + struct.pack("<I", threshold)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "stat_id": stat_id, "compare_value": threshold,
                "branch_prefix": prefix, "target_index": target_index, "editable": True,
            }
        if kind == STATE_REFERENCE_COMPARE_BRANCH_KIND:
            target_index = int(str(value).strip())
            source_stat_id = int(str(compare_value).strip())
            if stat_id not in STAT_TARGET_NAMES or source_stat_id not in STAT_TARGET_NAMES:
                raise ValueError("대상과 참조 상태값은 목록에 있는 상태값이어야 합니다.")
            if not 1 <= target_index <= 65535:
                raise ValueError("이동할 행은 1~65,535 범위여야 합니다.")
            prefix = b"\x43\x2B\x1C" + struct.pack("<H", stat_id) + b"\x1C" + struct.pack("<H", source_stat_id)
            return {
                "kind": kind, "raw": prefix + b"\0\0", "value": target_index,
                "stat_id": stat_id, "source_stat_id": source_stat_id,
                "branch_prefix": prefix, "target_index": target_index, "editable": True,
            }
        if kind in ("소지금 증가", "소지금 감소"):
            numeric_value = int(str(value).strip())
            if not 0 <= numeric_value <= 0xFFFFFFFF:
                raise ValueError("소지금 금액은 0~4,294,967,295 범위여야 합니다.")
            return {
                "kind": kind, "raw": (b"\x19\x14" if kind == "소지금 증가" else b"\x1A\x14") + struct.pack("<I", numeric_value),
                "value": numeric_value, "editable": True,
            }
        if kind == "상태값 참조 증가":
            if stat_id not in STAT_TARGET_NAMES:
                raise ValueError("실행 파일에서 처리되는 대상 상태값을 선택하세요.")
            if compare_value is None or not 0 <= int(compare_value) <= 0xFFFF:
                raise ValueError("참조 상태값 ID는 0~65,535 범위여야 합니다.")
            source_stat_id = int(compare_value)
            return {
                "kind": kind,
                "raw": b"\x19\x1C" + struct.pack("<H", stat_id) + b"\x1C" + struct.pack("<H", source_stat_id),
                "value": source_stat_id,
                "stat_id": stat_id,
                "source_stat_id": source_stat_id,
                "editable": True,
            }
        if kind in STAT_COMMAND_KINDS:
            if stat_id not in STAT_TARGET_NAMES:
                raise ValueError("실행 파일에서 처리되는 상태값 대상을 선택하세요.")
            value_text = str(value).strip()
            random_range = "~" in value_text
            if random_range:
                try:
                    first_text, last_text = (part.strip() for part in value_text.split("~", 1))
                    first, last = int(first_text), int(last_text)
                except ValueError as exc:
                    raise ValueError("무작위 범위는 예: 5~14 또는 -10~-29 형식으로 입력하세요.") from exc
                if kind == "상태값 설정" and (first < 0 or last < 0):
                    raise ValueError("설정값 범위는 0 이상이어야 합니다.")
                if kind == "상태값 증감" and (first < 0) != (last < 0):
                    raise ValueError("증감 범위의 두 값은 같은 부호여야 합니다.")
                magnitudes = abs(first), abs(last)
                if magnitudes[0] > magnitudes[1]:
                    raise ValueError("무작위 범위는 작은 절대값부터 큰 절대값 순으로 입력하세요.")
                numeric_value = first
                encoded_value = magnitudes[0]
                random_width = magnitudes[1] - magnitudes[0] + 1
            else:
                numeric_value = int(value_text)
            if kind == "상태값 증감":
                if not -0xFFFFFFFF <= numeric_value <= 0xFFFFFFFF:
                    raise ValueError("수치는 -4,294,967,295~4,294,967,295 범위여야 합니다.")
                opcode = 0x1A if numeric_value < 0 else 0x19
                if not random_range:
                    encoded_value = abs(numeric_value)
            else:
                if not 0 <= numeric_value <= 0xFFFFFFFF:
                    raise ValueError("설정값은 0~4,294,967,295 범위여야 합니다.")
                # 새 명령은 현재 파일에서 가장 널리 쓰이는 설정 형식(26 1C)으로 쓴다.
                opcode = 0x26
                if not random_range:
                    encoded_value = numeric_value
            expression = (
                b"\x20" + struct.pack("<I", random_width) + struct.pack("<I", encoded_value)
                if random_range else b"\x1A" + struct.pack("<I", encoded_value)
            )
            return {
                "kind": kind,
                "raw": bytes((opcode, 0x1C)) + struct.pack("<H", stat_id) + expression,
                "value": numeric_value,
                "value_text": value_text if random_range else None,
                "stat_id": stat_id,
                "stat_opcode": opcode,
                "editable": True,
            }
        if kind == "대기":
            numeric_value = int(str(value).strip())
            if not 0 <= numeric_value <= 0xFFFFFFFF:
                raise ValueError("대기 값은 0~4,294,967,295 범위여야 합니다.")
            return {
                "kind": kind,
                "raw": b"\x29\x1A" + struct.pack("<I", numeric_value),
                "value": numeric_value,
                "editable": True,
            }
        if kind == "날짜 경과":
            value_text = str(value).strip()
            if "~" in value_text:
                try:
                    first_text, last_text = (part.strip() for part in value_text.split("~", 1))
                    first, last = int(first_text), int(last_text)
                except ValueError as exc:
                    raise ValueError("랜덤 일수 범위는 예: 5~9 형식으로 입력하세요.") from exc
                if not 0 <= first <= last <= 0xFFFFFFFF:
                    raise ValueError("날짜 경과 일수는 0~4,294,967,295 범위여야 합니다.")
                width = last - first + 1
                if width > 0xFFFFFFFF:
                    raise ValueError("랜덤 일수 범위가 너무 큽니다.")
                raw = b"\x32\x20" + struct.pack("<I", width) + struct.pack("<I", first)
                return {
                    "kind": kind, "raw": raw, "value": first, "value_text": value_text, "editable": True,
                }
            numeric_value = int(value_text)
            if not 0 <= numeric_value <= 0xFFFFFFFF:
                raise ValueError("날짜 경과 일수는 0~4,294,967,295 범위여야 합니다.")
            return {
                "kind": kind, "raw": b"\x32\x1A" + struct.pack("<I", numeric_value),
                "value": numeric_value, "editable": True,
            }
        prefixes = {
            "AVI 재생": b"\x00\x02", "발견물 등록/발견 처리": b"\x01\x0B",
            "아이템 획득": b"\x00\x05", "아이템 상실": b"\x57\x05", "이벤트 아이템 등록": b"\x05\x05", "이벤트 아이템 처리": b"\x26\x05",
            "음원 재생": b"\x0E\x03", "음원 정지": b"\x66\x03", "이벤트 판정": b"\x0E\x04",
            "DSTILL 이미지 표시": b"\x00\x01",
            "EVSTILL 이미지 표시": b"\x00\x1F",
            "CG 애니메이션 재생": b"\x00\x0C",
        }
        if kind in prefixes:
            text = value.strip()
            numeric_value = 0 if not text else int(text)
            maximum = 15 if kind == "EVSTILL 이미지 표시" else 65535
            if not 0 <= numeric_value <= maximum:
                raise ValueError(f"값은 0~{maximum} 범위여야 합니다.")
            return {
                "kind": kind,
                "raw": prefixes[kind] + struct.pack("<H", numeric_value),
                "value": numeric_value,
                "editable": True,
            }
        code = int(kind.rsplit(" ", 1)[1])
        return {"kind": kind, "raw": bytes((0x4C + code,)), "value": None, "editable": True}

    def _add_body_command(self) -> None:
        kind = self._builder_body_kind()
        if kind not in BODY_COMMAND_KINDS:
            messagebox.showerror(ui("body_add_failed"), ui("select_command_to_add"), parent=self.root)
            return
        try:
            character_id = self._body_npc_id(self.sponsor_targets if self.body_detail_var.get() == "후원자" else self.character_targets) if kind == NPC_BRANCH_KIND else self._body_npc_id() if kind == "대상 지정 대사" or kind in CHARACTER_TARGET_COMMAND_KINDS else self._body_city_id() if kind == CITY_BRANCH_KIND else int(self.body_range_end_var.get().strip()) if kind == RUNTIME_REFERENCE_BRANCH_KIND else self._body_character_id() if kind in ("발견물 이름 설정", DISCOVERY_BRANCH_KIND, DISCOVERY_REGISTRATION_BRANCH_KIND) else None
            speaker_prefix = self._body_speaker_prefix() if kind in DIALOGUE_KINDS else b""
            stat_id = self._body_stat_id() if kind in STAT_COMMAND_KINDS + STAT_REFERENCE_COMMAND_KINDS + NUMERIC_COMPARE_BRANCH_KINDS + (STATE_REFERENCE_COMPARE_BRANCH_KIND,) else None
            token = self._new_body_token(
                kind, self._body_input_value(kind), character_id, stat_id,
                hint_id=self._body_hint_id() if kind in (HINT_BRANCH_KIND, "힌트 획득") else None,
                item_id=self._body_item_id() if kind in (ITEM_POSSESSION_BRANCH_KIND, ITEM_ABSENCE_BRANCH_KIND) else None,
                hint_active=self.body_hint_state_var.get() == "활성", speaker_prefix=speaker_prefix,
                compare_value=self.special_difficulty_var.get().strip() if kind == "특수 수치 판정" else int(self.body_value_var.get().strip()) if kind in STAT_REFERENCE_COMMAND_KINDS else f"{self.body_value2_var.get().strip()}~{self.body_range_end_var.get().strip()}" if kind == YEAR_RANGE_BRANCH_KIND else self.body_value2_var.get().strip() if kind in RANDOM_STATE_COMPARE_BRANCH_KINDS + (YEAR_BRANCH_KIND, YEAR_UPPER_BRANCH_KIND) else int(self.body_value2_var.get().strip()) if kind in NUMERIC_COMPARE_BRANCH_KINDS + (STATE_REFERENCE_COMPARE_BRANCH_KIND, "소지금 비교 분기", RUNTIME_REFERENCE_BRANCH_KIND) else None,
                choice_value=int(self.body_value2_var.get().strip()) if kind == CHOICE_BRANCH_KIND else None,
                npc_type=0x12 if kind == NPC_BRANCH_KIND and self.body_detail_var.get() == "후원자" else 0x0D,
            )
        except (UnicodeEncodeError, ValueError) as exc:
            messagebox.showerror(ui("body_add_failed"), str(exc), parent=self.root)
            return
        position = len(self.body_tokens) - 1 if self.body_tokens and self.body_tokens[-1]["kind"] == "본문 끝" else len(self.body_tokens)
        self._shift_branch_targets_for_insert(position)
        self.body_tokens.insert(position, token)
        self.selected_body_index = position
        self.pending = True
        self._refresh_body_list_selection()

    def _insert_body_command(self) -> None:
        if self.selected_body_index is None:
            messagebox.showerror(ui("body_insert_failed"), ui("select_body_to_insert"), parent=self.root)
            return
        kind = self._builder_body_kind()
        if kind not in BODY_COMMAND_KINDS:
            messagebox.showerror(ui("body_insert_failed"), ui("select_command_to_insert"), parent=self.root)
            return
        try:
            character_id = self._body_npc_id(self.sponsor_targets if self.body_detail_var.get() == "후원자" else self.character_targets) if kind == NPC_BRANCH_KIND else self._body_npc_id() if kind == "대상 지정 대사" or kind in CHARACTER_TARGET_COMMAND_KINDS else self._body_city_id() if kind == CITY_BRANCH_KIND else self._body_character_id() if kind in ("발견물 이름 설정", DISCOVERY_BRANCH_KIND, DISCOVERY_REGISTRATION_BRANCH_KIND) else None
            speaker_prefix = self._body_speaker_prefix() if kind in DIALOGUE_KINDS else b""
            stat_id = self._body_stat_id() if kind in STAT_COMMAND_KINDS + STAT_REFERENCE_COMMAND_KINDS + NUMERIC_COMPARE_BRANCH_KINDS + (STATE_REFERENCE_COMPARE_BRANCH_KIND,) else None
            token = self._new_body_token(
                kind, self._body_input_value(kind), character_id, stat_id,
                hint_id=self._body_hint_id() if kind in (HINT_BRANCH_KIND, "힌트 획득") else None,
                item_id=self._body_item_id() if kind in (ITEM_POSSESSION_BRANCH_KIND, ITEM_ABSENCE_BRANCH_KIND) else None,
                hint_active=self.body_hint_state_var.get() == "활성", speaker_prefix=speaker_prefix,
                compare_value=self.special_difficulty_var.get().strip() if kind == "특수 수치 판정" else int(self.body_value_var.get().strip()) if kind in STAT_REFERENCE_COMMAND_KINDS else f"{self.body_value2_var.get().strip()}~{self.body_range_end_var.get().strip()}" if kind == YEAR_RANGE_BRANCH_KIND else self.body_value2_var.get().strip() if kind in RANDOM_STATE_COMPARE_BRANCH_KINDS + (YEAR_BRANCH_KIND,) else int(self.body_value2_var.get().strip()) if kind in NUMERIC_COMPARE_BRANCH_KINDS + (STATE_REFERENCE_COMPARE_BRANCH_KIND,) else None,
                choice_value=int(self.body_value2_var.get().strip()) if kind == CHOICE_BRANCH_KIND else None,
                npc_type=0x12 if kind == NPC_BRANCH_KIND and self.body_detail_var.get() == "후원자" else 0x0D,
            )
        except (UnicodeEncodeError, ValueError) as exc:
            messagebox.showerror(ui("body_insert_failed"), str(exc), parent=self.root)
            return
        self._shift_branch_targets_for_insert(self.selected_body_index)
        self.body_tokens.insert(self.selected_body_index, token)
        self.pending = True
        self._refresh_body_list_selection()

    def _remove_body_command(self) -> None:
        if self.selected_body_index is None:
            messagebox.showerror(ui("body_remove_failed"), ui("select_body_to_remove"), parent=self.root)
            return
        if self.body_tokens[self.selected_body_index]["kind"] == "본문 끝":
            messagebox.showerror(ui("body_remove_failed"), ui("body_end_cannot_remove"), parent=self.root)
            return
        removed_index = self.selected_body_index
        self.body_tokens.pop(removed_index)
        self._shift_branch_targets_for_remove(removed_index)
        self.selected_body_index = min(self.selected_body_index, len(self.body_tokens) - 1)
        if self.selected_body_index is not None and self.body_tokens[self.selected_body_index]["kind"] == "본문 끝":
            self.selected_body_index = self.selected_body_index - 1 if self.selected_body_index else None
        self.pending = True
        self._refresh_body_list_selection()

    def _load_condition_builder(self, condition: bytes) -> None:
        self.condition_tokens = self._decode_condition_tokens(condition)
        self.selected_condition_index = None
        editable = self.condition_tokens is not None
        self.condition_kind_combo.configure(state="readonly" if editable else "disabled")
        self.condition_edit_button.configure(state="normal" if editable else "disabled")
        self.condition_add_button.configure(state="normal" if editable else "disabled")
        self.condition_insert_button.configure(state="normal" if editable else "disabled")
        self.condition_remove_button.configure(state="normal" if editable else "disabled")
        self.condition_clear_button.configure(state="normal" if editable else "disabled")
        for widget in self.condition_value_spins:
            widget.configure(state="normal" if editable else "disabled")
        self.condition_target_combo.configure(state="readonly" if editable else "disabled")
        if editable:
            self._condition_kind_changed()
        else:
            self.condition_summary_var.set("미확인 opcode가 포함돼 조건 편집을 잠갔습니다. 원본 조건은 그대로 보존됩니다.")
        self._refresh_condition_display()

    def _token_from_builder(self) -> tuple[str, tuple[int, ...]] | None:
        kind = self._builder_condition_kind()
        fields, _encoder = CONDITION_KINDS[kind]
        if kind == "항상 실행":
            return None
        if kind == "또는 (OR)":
            return kind, ()
        if self._condition_named_targets(kind):
            selected = self.condition_target_var.get().split("|", 1)[0].strip()
            if not selected:
                raise ValueError("목록에서 조건 대상을 선택하세요.")
            return kind, (int(selected),)
        values = tuple(int(self.condition_value_vars[index].get().strip()) for index in range(len(fields)))
        for value, (_name, minimum, maximum) in zip(values, fields):
            if not minimum <= value <= maximum:
                raise ValueError(f"조건 값은 {minimum}~{maximum} 범위여야 합니다.")
        return kind, values

    def _add_condition_token(self) -> None:
        if self.condition_tokens is None:
            return
        try:
            token = self._token_from_builder()
            if token is None:
                self.condition_tokens.clear()
                selected = None
            elif token[0] == "또는 (OR)":
                if not self.condition_tokens or self.condition_tokens[-1][0] == "또는 (OR)":
                    raise ValueError("OR는 첫 조건 또는 OR 바로 뒤에 둘 수 없습니다.")
                self.condition_tokens.append(token)
                selected = len(self.condition_tokens) - 1
            else:
                self.condition_tokens.append(token)
                selected = len(self.condition_tokens) - 1
        except ValueError as exc:
            messagebox.showerror(ui("condition_add_failed"), str(exc), parent=self.root)
            return
        self._refresh_condition_display(selected)
        self.pending = True
        self.status_var.set(ui("status_condition_added"))

    def _apply_condition_token(self) -> None:
        if self.condition_tokens is None or self.selected_condition_index is None:
            messagebox.showerror(ui("condition_edit_failed"), ui("select_condition_to_edit"), parent=self.root)
            return
        try:
            token = self._token_from_builder()
            if token is None:
                raise ValueError("'항상 실행'은 조건 목록의 항목으로 수정할 수 없습니다.")
            candidate = list(self.condition_tokens)
            candidate[self.selected_condition_index] = token
            if candidate[0][0] == "또는 (OR)" or candidate[-1][0] == "또는 (OR)":
                raise ValueError("OR는 첫 번째 또는 마지막 조건일 수 없습니다.")
            if any(
                candidate[index][0] == "또는 (OR)" and candidate[index + 1][0] == "또는 (OR)"
                for index in range(len(candidate) - 1)
            ):
                raise ValueError("OR는 OR 바로 뒤에 둘 수 없습니다.")
            self.condition_tokens = candidate
        except ValueError as exc:
            messagebox.showerror(ui("condition_edit_failed"), str(exc), parent=self.root)
            return
        self._refresh_condition_display(self.selected_condition_index)
        self.pending = True
        self.status_var.set(ui("status_condition_updated"))

    def _insert_condition_token(self) -> None:
        if self.condition_tokens is None:
            return
        if self.selected_condition_index is None:
            messagebox.showerror(ui("condition_insert_failed"), ui("select_condition_to_insert"), parent=self.root)
            return
        try:
            token = self._token_from_builder()
            if token is None:
                raise ValueError("'항상 실행'은 조건 목록에 삽입할 수 없습니다.")
            if token[0] == "또는 (OR)" and self.selected_condition_index == 0:
                raise ValueError("OR는 첫 조건으로 삽입할 수 없습니다.")
            self.condition_tokens.insert(self.selected_condition_index, token)
        except ValueError as exc:
            messagebox.showerror(ui("condition_insert_failed"), str(exc), parent=self.root)
            return
        self._refresh_condition_display(self.selected_condition_index)
        self.pending = True
        self.status_var.set(ui("status_condition_inserted"))

    def _remove_selected_condition(self) -> None:
        if self.condition_tokens is None or self.selected_condition_index is None:
            messagebox.showerror(ui("condition_remove_failed"), ui("select_condition_to_remove"), parent=self.root)
            return
        index = self.selected_condition_index
        self.condition_tokens.pop(index)
        self._refresh_condition_display(min(index, len(self.condition_tokens) - 1))
        self.pending = True
        self.status_var.set(ui("status_condition_removed"))

    def _clear_conditions(self) -> None:
        if self.condition_tokens is not None:
            self.condition_tokens.clear()
            self._refresh_condition_display()
            self.pending = True

    def _encode_condition_tokens(self) -> bytes:
        if self.condition_tokens is None:
            raise ValueError("미확인 조건열은 구조 편집으로 변경할 수 없습니다.")
        if self.condition_tokens and self.condition_tokens[-1][0] == "또는 (OR)":
            raise ValueError("마지막 조건은 OR일 수 없습니다.")
        encoded = bytearray()
        for kind, values in self.condition_tokens:
            encoded.extend(CONDITION_KINDS[kind][1](values))
        encoded.append(0xFF)
        return bytes(encoded)

    def _open_disev(self) -> None:
        if not self._confirm_abandon_archive():
            return
        filename = filedialog.askopenfilename(
            parent=self.root,
            title=ui("open_disev_dialog_title"),
            filetypes=((ui("disev_event_file"), "DISEV.CDS"), (ui("cds_file"), "*.CDS"), (ui("all_files"), "*.*")),
        )
        if filename:
            self._load_archive(Path(filename))

    def _load_archive(self, path: Path) -> None:
        try:
            archive = path.read_bytes()
            entries = disev.parse_archive(archive)
            dictionary = archive[0x10:0x110]
            parts = [disev.decode_part(archive, entry, dictionary) for entry in entries]
            for index, part in enumerate(parts):
                disev.validate_part(part, index)
        except (OSError, ValueError, struct.error) as exc:
            messagebox.showerror(ui("open_failed"), str(exc), parent=self.root)
            return

        self.disev_path = path.resolve()
        self.archive = archive
        self.entries = entries
        self.parts = parts
        self.original_parts = list(parts)
        self.modified.clear()
        self.current_index = None
        self.current_discovery_id = None
        self.pending = False
        self.rows = []
        self.discovery_part_map = {}

        candidate = self.disev_path.with_name("CDS_95.EXE")
        if candidate.exists():
            self._load_exe_mapping(candidate, quiet=True)
        self._refresh_tree()
        self.root.title(f"{APP_TITLE} - [{self.disev_path.name}]")
        self.status_var.set(ui("status_loaded", len(parts)))
        self._update_dirty_status()
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.tree.focus(children[0])

    def _load_exe_mapping(self, path: Path, quiet: bool) -> None:
        try:
            rows = disev.load_discovery_rows(path.resolve())
            if self.parts and len(rows) != len(self.parts):
                raise ValueError(
                    f"EXE 발견물 {len(rows)}개와 DISEV 파트 {len(self.parts)}개가 일치하지 않습니다."
                )
        except (OSError, ValueError, struct.error) as exc:
            if not quiet:
                messagebox.showerror(ui("exe_mapping_failed"), str(exc), parent=self.root)
            return
        self.exe_path = path.resolve()
        self.rows = rows
        self.discovery_part_map = self._build_discovery_part_map(rows)
        self.discovery_targets = self._load_discovery_targets(rows)
        self.body_character_combo.configure(
            values=tuple(name for _item_id, name in self.discovery_targets)
        )
        if self.parts:
            self._refresh_tree(keep_index=self.current_index)
        self.status_var.set(ui("status_exe_mapped", len(self.discovery_part_map)))

    def _build_discovery_part_map(self, rows: list[disev.DiscoveryRow]) -> dict[int, int]:
        """EXE 발견물 목록을 DISEV 파트에 연결한다.

        발견물 등록/발견 처리(01 0B)가 있는 파트는 그 명령의 대상 ID를 우선한다.
        다만 원본에는 등록 처리가 없는 발견물 이벤트도 있으므로, 그런 항목은
        발견물 ID와 같은 번호의 파트를 기본 연결해 목록에서 숨기지 않는다.
        """
        valid_ids = {row.index for row in rows}
        candidates: dict[int, list[int]] = {}
        for part_index, part in enumerate(self.parts):
            cursor = 0
            while True:
                offset = part.find(b"\x01\x0B", cursor)
                if offset < 0 or offset + 4 > len(part):
                    break
                discovery_id = struct.unpack_from("<H", part, offset + 2)[0]
                if discovery_id in valid_ids:
                    candidates.setdefault(discovery_id, []).append(part_index)
                cursor = offset + 1
        mapping: dict[int, int] = {}
        for discovery_id, part_indexes in candidates.items():
            # 같은 ID의 복사 파트가 있으면 ID와 같은 번호를 우선하고,
            # 없으면 가장 앞의 실제 등록 후보를 연결한다.
            mapping[discovery_id] = (
                discovery_id if discovery_id in part_indexes else min(part_indexes)
            )
        for row in rows:
            if row.index not in mapping and 0 <= row.index < len(self.parts):
                mapping[row.index] = row.index
        return mapping

    def _row_for_discovery(self, discovery_id: int | None) -> disev.DiscoveryRow | None:
        if discovery_id is None:
            return None
        return next((row for row in self.rows if row.index == discovery_id), None)

    def _schedule_filter(self, *_args) -> None:
        if self.filter_after:
            self.root.after_cancel(self.filter_after)
        self.filter_after = self.root.after(80, self._refresh_tree)

    def _refresh_tree(self, keep_index: int | None = None) -> None:
        if not self.parts:
            return
        selected = self.current_discovery_id
        query = self.search_edit.get().strip().casefold()
        self.tree.delete(*self.tree.get_children())
        for row in self.rows:
            part_index = self.discovery_part_map.get(row.index)
            if part_index is None:
                continue
            name = row.name
            haystack = f"{row.index} {name} {row.game_id}".casefold()
            if query and query not in haystack:
                continue
            marker = "*" if part_index in self.modified else ""
            item = self.tree.insert(
                "",
                "end",
                iid=f"d{row.index}",
                values=(f"{row.index:03d}{marker}", name),
            )
            if row.index == selected:
                self.tree.selection_set(item)
                self.tree.focus(item)
        # insert 직후에는 Treeview 행 높이가 아직 계산되지 않을 수 있다.
        self.root.after(80, self._sync_tree_scrollbar)
        self.root.after_idle(self._autosize_discovery_tree_and_panel)

    def _select_part(self, _event=None) -> None:
        if self.loading_editor:
            return
        selection = self.tree.selection()
        if not selection:
            return
        discovery_id = int(selection[0][1:])
        index = self.discovery_part_map.get(discovery_id)
        row = self._row_for_discovery(discovery_id)
        if index is None or row is None:
            return
        if discovery_id == self.current_discovery_id:
            return
        if self.pending and self.current_index is not None:
            answer = messagebox.askyesnocancel(
                ui("pending_edit"),
                ui("apply_before_move_prompt"),
                parent=self.root,
            )
            if answer is None:
                self.loading_editor = True
                self.tree.selection_set(f"d{self.current_discovery_id}")
                self.tree.focus(f"d{self.current_discovery_id}")
                self.loading_editor = False
                return
            if answer and not self._apply_editor():
                self.loading_editor = True
                self.tree.selection_set(f"d{self.current_discovery_id}")
                self.tree.focus(f"d{self.current_discovery_id}")
                self.loading_editor = False
                return
        self._load_part(index, row)

    def _load_part(self, index: int, row: disev.DiscoveryRow | None = None) -> None:
        part = self.parts[index]
        step, slots = disev.validate_part(part, index)
        if len(slots) != 1:
            messagebox.showerror(ui("unsupported_structure"), ui("one_slot_only"), parent=self.root)
            return
        condition_start, body_start = slots[0]
        self.current_index = index
        if row is not None:
            self.current_discovery_id = row.index
        self.loading_editor = True
        self._set_edit_state(True)
        row = row or self._row_for_discovery(self.current_discovery_id)
        stored_condition = part[condition_start:body_start]
        self._load_condition_builder(stored_condition)
        self._show_body_commands(part, body_start, row)
        self.pending = False
        self.loading_editor = False
        self.status_var.set(ui("status_part_selected", index, row.name if row else ui("unmapped")))

    def _show_body_commands(self, part: bytes, body_start: int, row: disev.DiscoveryRow | None) -> None:
        self.body_tokens = self._decode_body_tokens(part[body_start:])
        self.selected_body_index = None
        self.body_tree.delete(*self.body_tree.get_children())
        for index, token in enumerate(self.body_tokens):
            if token["kind"] == "본문 끝":
                continue
            self.body_tree.insert(
                "", "end", iid=str(index),
                values=(index + 1, *self._body_display_levels(token), self._body_display_value(token)),
            )
        self.body_command_var.set("-")
        self.body_value_var.set("")
        self._body_kind_changed()
        self.body_value_entry.configure(state="disabled")
        self.body_character_combo.configure(state="disabled")
        self.body_item_combo.configure(state="disabled")
        self.body_city_combo.configure(state="disabled")
        self.body_stat_target_combo.configure(state="disabled")
        self.body_hint_state_combo.configure(state="disabled")
        self.body_hint_combo.configure(state="disabled")
        self.body_edit_button.configure(state="disabled")
        self.root.after_idle(lambda: self._autosize_tree_columns(self.body_tree, skip=("value",)))

    @staticmethod
    def _decode_body_tokens(body: bytes) -> list[dict[str, object]]:
        """본문을 명령 행으로 나누되, 알 수 없는 바이트도 원본 그대로 보존한다."""
        tokens: list[dict[str, object]] = []
        i = 0
        while i < len(body):
            if body[i] == 0xFF:
                tokens.append({"kind": "본문 끝", "raw": b"\xFF", "value": None, "editable": False})
                i += 1
                continue
            # 43 [0F/12] 0E [힌트 u16] [상대 이동 u16]: 힌트 상태 조건 분기.
            if (
                i + 7 <= len(body)
                and body[i] == 0x43
                and body[i + 1] in (0x0F, 0x12)
                and body[i + 2] == 0x0E
            ):
                hint_id = struct.unpack_from("<H", body, i + 3)[0]
                tokens.append({
                    "kind": HINT_BRANCH_KIND, "raw": body[i:i + 7], "value": None,
                    "hint_id": hint_id, "hint_active": body[i + 1] == 0x0F,
                    "branch_prefix": body[i:i + 5], "editable": True,
                })
                i += 7
                continue
            # 43 3A 0B [발견물 u16] [상대 이동 u16]: 발견물 상태 조건 분기.
            if i + 7 <= len(body) and body[i:i + 3] == b"\x43\x3A\x0B":
                character_id = struct.unpack_from("<H", body, i + 3)[0]
                tokens.append({
                    "kind": DISCOVERY_BRANCH_KIND, "raw": body[i:i + 7], "value": None,
                    "character_id": character_id, "branch_prefix": body[i:i + 5], "editable": True,
                })
                i += 7
                continue
            # 43 02 0B [발견물 u16] [상대 이동 u16]: 발견물 등록 여부를 판정해 거짓이면 분기한다.
            if i + 7 <= len(body) and body[i:i + 3] == b"\x43\x02\x0B":
                character_id = struct.unpack_from("<H", body, i + 3)[0]
                tokens.append({
                    "kind": DISCOVERY_REGISTRATION_BRANCH_KIND, "raw": body[i:i + 7], "value": None,
                    "character_id": character_id, "branch_prefix": body[i:i + 5], "editable": True,
                })
                i += 7
                continue
            # 43 36 16 [시작 연도] 16 [종료 연도] [상대 이동]: 연도 범위 조건이 거짓이면 분기한다.
            if i + 10 <= len(body) and body[i : i + 3] == b"\x43\x36\x16" and body[i + 5] == 0x16:
                start_year = struct.unpack_from("<H", body, i + 3)[0]
                end_year = struct.unpack_from("<H", body, i + 6)[0]
                tokens.append({
                    "kind": YEAR_RANGE_BRANCH_KIND, "raw": body[i : i + 10], "value": None,
                    "start_year": start_year, "end_year": end_year,
                    "branch_prefix": body[i : i + 8], "editable": True,
                })
                i += 10
                continue
            # 43 1B 16 [기준 연도] [상대 이동]: 기준 연도 조건이 거짓이면 분기한다.
            if i + 7 <= len(body) and body[i : i + 3] == b"\x43\x1B\x16":
                year = struct.unpack_from("<H", body, i + 3)[0]
                tokens.append({"kind": YEAR_BRANCH_KIND, "raw": body[i : i + 7], "value": None, "year": year, "branch_prefix": body[i : i + 5], "editable": True})
                i += 7
                continue
            # 43 39 16 [상한 연도] [상대 이동]: 상한 연도 조건이 거짓이면 분기한다.
            if i + 7 <= len(body) and body[i : i + 3] == b"\x43\x39\x16":
                year = struct.unpack_from("<H", body, i + 3)[0]
                tokens.append({"kind": YEAR_UPPER_BRANCH_KIND, "raw": body[i : i + 7], "value": None, "year": year, "branch_prefix": body[i : i + 5], "editable": True})
                i += 7
                continue
            # 43 2F 0D [인물 u16] [상대 이동]: 보조 인물 이벤트 결과에 따른 분기.
            # 보조 이벤트 자체의 세부 결과 규칙이 확정되기 전까지 읽기 전용으로 유지한다.
            if i + 8 <= len(body) and body[i : i + 3] == b"\x43\x2F\x0D":
                character_id = struct.unpack_from("<H", body, i + 3)[0]
                tokens.append({"kind": f"보조 인물 이벤트 조건 이동: 인물 ID {character_id}", "raw": body[i : i + 8], "value": None, "editable": False})
                i += 8
                continue
            # 43 0F/12 05 [아이템 u16] [상대 이동]: 아이템 소지 여부 조건이 거짓이면 분기한다.
            if i + 7 <= len(body) and body[i : i + 2] == b"\x43\x0F" and body[i + 2] == 0x05 or (
                i + 7 <= len(body) and body[i : i + 2] == b"\x43\x12" and body[i + 2] == 0x05
            ):
                item_id = struct.unpack_from("<H", body, i + 3)[0]
                kind = ITEM_POSSESSION_BRANCH_KIND if body[i + 1] == 0x12 else ITEM_ABSENCE_BRANCH_KIND
                tokens.append({
                    "kind": kind, "raw": body[i : i + 7], "value": None,
                    "item_id": item_id, "branch_prefix": body[i : i + 5], "editable": True,
                })
                i += 7
                continue
            # 43 17 08 [도시 u16] [상대 이동 u16]: 도시 조건이 거짓이면 분기한다.
            if i + 7 <= len(body) and body[i : i + 3] == b"\x43\x17\x08":
                city_id = struct.unpack_from("<H", body, i + 3)[0]
                tokens.append({
                    "kind": CITY_BRANCH_KIND, "raw": body[i : i + 7], "value": None,
                    "character_id": city_id, "branch_prefix": body[i : i + 5], "editable": True,
                })
                i += 7
                continue
            # 43 37 0D/12 [인물/후원자 u16] [상대 이동 u16]: NPC 조건이 거짓이면 분기한다.
            if i + 7 <= len(body) and body[i : i + 2] == b"\x43\x37" and body[i + 2] in (0x0D, 0x12):
                npc_type = body[i + 2]
                character_id = struct.unpack_from("<H", body, i + 3)[0]
                tokens.append({
                    "kind": NPC_BRANCH_KIND, "raw": body[i : i + 7], "value": None,
                    "character_id": character_id, "npc_type": npc_type,
                    "branch_prefix": body[i : i + 5], "editable": True,
                })
                i += 7
                continue
            if i + 4 <= len(body) and body[i : i + 2] == b"\x26\x08":
                city_id = struct.unpack_from("<H", body, i + 2)[0]
                tokens.append({
                    "kind": "신도시 생성",
                    "raw": body[i : i + 4],
                    "value": city_id,
                    "editable": True,
                })
                i += 4
                continue
            # 26 0F [u16]: 유적·민족·인물 이벤트에서 쓰는 내부 분류값을 설정한다.
            if i + 4 <= len(body) and body[i : i + 2] == b"\x26\x0F":
                tokens.append({"kind": "이벤트 분류 설정", "raw": body[i : i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 26 1C 1A 00 08 [인물 u16]: 이벤트가 사용할 역사 인물 참조를 설정한다.
            if i + 7 <= len(body) and body[i : i + 5] == b"\x26\x1C\x1A\0\x08":
                character_id = struct.unpack_from("<H", body, i + 5)[0]
                tokens.append({
                    "kind": "인물 참조 설정", "raw": body[i : i + 7], "value": character_id,
                    "character_id": character_id, "editable": True,
                })
                i += 7
                continue
            # 23 08 [인물 u16]: 인물 런타임 상태의 세 번째 처리 형식.
            if i + 4 <= len(body) and body[i : i + 2] == b"\x23\x08":
                character_id = struct.unpack_from("<H", body, i + 2)[0]
                tokens.append({
                    "kind": "인물 상태 처리 3", "raw": body[i : i + 4], "value": character_id,
                    "character_id": character_id, "editable": True,
                })
                i += 4
                continue
            # 22 10 [비트 u16] 08 [인물 u16]: 지정 인물의 상태 비트를 해제한다.
            if i + 7 <= len(body) and body[i : i + 2] == b"\x22\x10" and body[i + 4] == 0x08:
                bit_index = struct.unpack_from("<H", body, i + 2)[0]
                character_id = struct.unpack_from("<H", body, i + 5)[0]
                tokens.append({"kind": "인물 상태 비트 해제", "raw": body[i : i + 7], "value": bit_index, "character_id": character_id, "editable": bit_index <= 15})
                i += 7
                continue
            # 22 08 [인물 u16]: 인물 런타임 상태의 네 번째 처리 형식(상태 비트 0x04 설정).
            if i + 4 <= len(body) and body[i : i + 2] == b"\x22\x08":
                character_id = struct.unpack_from("<H", body, i + 2)[0]
                tokens.append({"kind": "인물 상태 처리 4", "raw": body[i : i + 4], "value": character_id, "character_id": character_id, "editable": True})
                i += 4
                continue
            # 22 00 [u16]: 내부 런타임 상태 항목을 설정한다.
            if i + 4 <= len(body) and body[i : i + 2] == b"\x22\x00":
                tokens.append({"kind": "내부 상태 설정", "raw": body[i : i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 34 1C 02 00 1A [u32]: 파라과이족 이벤트에서 확인된 내부 특수 상태 처리.
            if i + 9 <= len(body) and body[i : i + 5] == b"\x34\x1C\x02\0\x1A":
                tokens.append({"kind": "특수 상태 처리", "raw": body[i : i + 9], "value": struct.unpack_from("<I", body, i + 5)[0], "editable": True})
                i += 9
                continue
            # 2F 08 [인물 u16]: 지정 인물을 대상으로 선택 창을 열고 결과를 판정한다.
            if i + 4 <= len(body) and body[i : i + 2] == b"\x2F\x08":
                character_id = struct.unpack_from("<H", body, i + 2)[0]
                tokens.append({"kind": "인물 선택 판정", "raw": body[i : i + 4], "value": character_id, "character_id": character_id, "editable": True})
                i += 4
                continue
            # 3C 08 [인물 u16]: 지정 인물의 위치·상태를 대상으로 판정한다.
            if i + 4 <= len(body) and body[i : i + 2] == b"\x3C\x08":
                character_id = struct.unpack_from("<H", body, i + 2)[0]
                tokens.append({"kind": "인물 위치 판정", "raw": body[i : i + 4], "value": character_id, "character_id": character_id, "editable": True})
                i += 4
                continue
            # 0D 0D [u16]: 지정한 해양 괴물/조우 상대와 전투를 시작한다.
            if i + 4 <= len(body) and body[i : i + 2] == b"\x0D\x0D":
                tokens.append({"kind": "해상 전투", "raw": body[i : i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 38/3D 0D [인물 u16]: 역사 인물의 런타임 상태를 처리한다.
            # 3D는 현재 파일에서 항상 38 바로 앞에만 쓰인다. 정확한 내부 상태의
            # 이름은 확정되지 않아 순서대로 처리 1/2로 보존한다.
            if i + 4 <= len(body) and body[i + 1] == 0x0D and body[i] in (0x38, 0x3D):
                kind = "인물 상태 처리 1" if body[i] == 0x38 else "인물 상태 처리 2"
                character_id = struct.unpack_from("<H", body, i + 2)[0]
                tokens.append({
                    "kind": kind, "raw": body[i : i + 4], "value": character_id,
                    "character_id": character_id, "editable": True,
                })
                i += 4
                continue
            # 0C/2F 0D [u16]: 인물 타입 ID를 대상으로 하는 서로 다른 이벤트 처리.
            if i + 4 <= len(body) and body[i + 1] == 0x0D and body[i] in (0x0C, 0x2F):
                kind = "인물 이벤트 실행" if body[i] == 0x0C else "인물 이벤트 실행 (보조)"
                tokens.append({"kind": kind, "raw": body[i : i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 30 1D [u16]: 분기와 발견 처리 사이에서 쓰는 내부 이벤트 참조값.
            if i + 4 <= len(body) and body[i : i + 2] == b"\x30\x1D":
                tokens.append({"kind": "이벤트 내부 참조", "raw": body[i : i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 35 1C [u16]: 내부 조건을 판정하고 바로 뒤 결과 분기에 성공/실패를 제공한다.
            if i + 4 <= len(body) and body[i : i + 2] == b"\x35\x1C":
                tokens.append({"kind": "이벤트 조건 판정", "raw": body[i : i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 01 15 [u16]은 전역 이벤트 플래그 배열의 항목을 1로 설정한다.
            if i + 4 <= len(body) and body[i : i + 2] == b"\x01\x15":
                flag_id = struct.unpack_from("<H", body, i + 2)[0]
                tokens.append({
                    "kind": "이벤트 플래그 설정",
                    "raw": body[i : i + 4],
                    "value": flag_id,
                    "editable": True,
                })
                i += 4
                continue
            # 1F는 발견물 런타임 레코드의 이름을 바꾸는 복합 명령이다.
            # 두 배열 형식이 있으며, 편집 후에도 읽어 온 형식을 보존한다.
            if i + 5 <= len(body) and body[i : i + 2] == b"\x1F\x0B" and body[i + 4] == 0x0A:
                character_id = struct.unpack_from("<H", body, i + 2)[0]
                text_start = i + 5
                end = body.find(b"\0", text_start)
                if end >= 0:
                    source = body[text_start:end]
                    marker = source.find(b"\x81\x46", 0, min(len(source), 40))
                    speaker_prefix = source[: marker + 2] if marker >= 0 else b""
                    _speaker, text = disev.decode_dialogue(source)
                    tokens.append({
                        "kind": "발견물 이름 설정",
                        "raw": body[i : end + 1],
                        "value": text,
                        "character_id": character_id,
                        "dialogue_layout": "id_first",
                        "speaker_prefix": speaker_prefix,
                        "editable": True,
                    })
                    i = end + 1
                    continue
            if i + 2 <= len(body) and body[i : i + 2] == b"\x1F\x0A":
                text_start = i + 2
                end = body.find(b"\0", text_start)
                if end >= 0 and end + 4 <= len(body) and body[end + 1] == 0x0B:
                    character_id = struct.unpack_from("<H", body, end + 2)[0]
                    source = body[text_start:end]
                    marker = source.find(b"\x81\x46", 0, min(len(source), 40))
                    speaker_prefix = source[: marker + 2] if marker >= 0 else b""
                    _speaker, text = disev.decode_dialogue(source)
                    tokens.append({
                        "kind": "발견물 이름 설정",
                        "raw": body[i : end + 4],
                        "value": text,
                        "character_id": character_id,
                        "dialogue_layout": "text_first",
                        "speaker_prefix": speaker_prefix,
                        "editable": True,
                    })
                    i = end + 4
                    continue
            # 10/18 0A [CP949 문자열] 00 [선택지 수(통상 0)]: 다중 선택지 대사.
            # 18은 세 개 이상 선택지가 있는 대화에서 확인된 창 형식이며,
            # 뒤따르는 43 11 0A [선택값] 분기들이 각 항목의 결과를 처리한다.
            if i + 3 <= len(body) and body[i] in (0x10, 0x18) and body[i + 1] == 0x0A:
                text_start = i + 2
                end = body.find(b"\0", text_start)
                if end >= 0 and end + 1 < len(body):
                    source = body[text_start:end]
                    marker = source.find(b"\x81\x46", 0, min(len(source), 40))
                    speaker_prefix = source[: marker + 2] if marker >= 0 else b""
                    _speaker, text = disev.decode_dialogue(source)
                    tokens.append({
                        "kind": "다중 선택지 대사", "raw": body[i : end + 2], "value": text,
                        "speaker_prefix": speaker_prefix, "editable": True, "flag": body[i],
                        "choice_count": body[end + 1],
                    })
                    i = end + 2
                    continue
            # 20 0A [문자열] 00 08 [인물 u16]: 대사와 함께 런타임 인물 대상을 지정한다.
            if i + 8 <= len(body) and body[i : i + 2] == b"\x20\x0A":
                text_start = i + 2
                end = body.find(b"\0", text_start)
                if end >= 0 and end + 4 <= len(body) and body[end + 1] == 0x08:
                    source = body[text_start:end]
                    marker = source.find(b"\x81\x46", 0, min(len(source), 40))
                    speaker_prefix = source[: marker + 2] if marker >= 0 else b""
                    _speaker, text = disev.decode_dialogue(source)
                    character_id = struct.unpack_from("<H", body, end + 2)[0]
                    tokens.append({
                        "kind": "대상 지정 대사", "raw": body[i : end + 4], "value": text,
                        "character_id": character_id, "speaker_prefix": speaker_prefix,
                        "editable": True, "flag": 0x20,
                    })
                    i = end + 4
                    continue
            # 일반 대사 또는 창 플래그가 붙은 대사.
            if body[i] == 0x0A or (i + 1 < len(body) and body[i + 1] == 0x0A):
                flag = None if body[i] == 0x0A else body[i]
                text_start = i + 1 if flag is None else i + 2
                end = body.find(b"\0", text_start)
                if end < 0:
                    end = len(body)
                    next_i = end
                else:
                    next_i = end + 1
                source = body[text_start:end]
                marker = source.find(b"\x81\x46", 0, min(len(source), 40))
                speaker_prefix = source[: marker + 2] if marker >= 0 else b""
                _speaker, text = disev.decode_dialogue(source)
                tokens.append({
                    "kind": "예/아니오 대사" if flag == 0x0B else "대사",
                    "raw": body[i:next_i],
                    "value": text,
                    "speaker_prefix": speaker_prefix,
                    "editable": True,
                    "flag": flag,
                })
                i = next_i
                continue
            if i + 4 <= len(body) and body[i:i + 2] == b"\x00\x02":
                tokens.append({"kind": "AVI 재생", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 00 01 [u16]: DSTILL 이미지를 표시한다.
            if i + 4 <= len(body) and body[i:i + 2] == b"\x00\x01":
                tokens.append({"kind": "DSTILL 이미지 표시", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 00 0C [u16]: CG 애니메이션을 재생한다.
            if i + 4 <= len(body) and body[i:i + 2] == b"\x00\x0C":
                tokens.append({"kind": "CG 애니메이션 재생", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 00 1E [u16]: 동물·자연현상·유령선 등 특수 조우의 연출 종류를 지정한다.
            if i + 4 <= len(body) and body[i:i + 2] == b"\x00\x1E":
                tokens.append({"kind": "특수 조우 연출 설정", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            if i + 4 <= len(body) and body[i:i + 2] == b"\x01\x0B":
                tokens.append({"kind": "발견물 등록/발견 처리", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            if i + 4 <= len(body) and body[i:i + 2] in (b"\x00\x05", b"\x57\x05"):
                kind = "아이템 획득" if body[i] == 0x00 else "아이템 상실"
                tokens.append({"kind": kind, "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 05 05 [u16]: 직전 획득한 아이템을 이벤트용으로 추가 등록한다.
            if i + 4 <= len(body) and body[i:i + 2] == b"\x05\x05":
                tokens.append({"kind": "이벤트 아이템 등록", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 26 05 [u16]: 아이템을 대상으로 이벤트 전용 처리를 실행한다.
            if i + 4 <= len(body) and body[i:i + 2] == b"\x26\x05":
                tokens.append({"kind": "이벤트 아이템 처리", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            if i + 4 <= len(body) and body[i:i + 2] == b"\x0E\x03":
                tokens.append({"kind": "음원 재생", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 0E 04 [u16]: 내부 이벤트 판정을 실행하고 뒤 분기용 결과를 설정한다.
            if i + 4 <= len(body) and body[i:i + 2] == b"\x0E\x04":
                tokens.append({"kind": "이벤트 판정", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 0E 14 [판정값 u32] 04 [난이도 u16]: 유적·함정 이벤트의 수치 판정.
            if i + 9 <= len(body) and body[i:i + 2] == b"\x0E\x14" and body[i + 6] == 0x04:
                tokens.append({
                    "kind": "특수 수치 판정", "raw": body[i:i + 9],
                    "value": struct.unpack_from("<I", body, i + 2)[0],
                    "difficulty": struct.unpack_from("<H", body, i + 7)[0], "editable": True,
                })
                i += 9
                continue
            # 05 0E [힌트 u16]: 발견물 힌트를 획득(활성)한다.
            if i + 4 <= len(body) and body[i:i + 2] == b"\x05\x0E":
                tokens.append({"kind": "힌트 획득", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 66 03 [u16]: 현재 재생 중인 음원과 지정한 음원 ID를 정지한다.
            if i + 4 <= len(body) and body[i:i + 2] == b"\x66\x03":
                tokens.append({"kind": "음원 정지", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            if i + 4 <= len(body) and body[i:i + 2] == b"\x00\x1F":
                tokens.append({"kind": "EVSTILL 이미지 표시", "raw": body[i:i + 4], "value": struct.unpack_from("<H", body, i + 2)[0], "editable": True})
                i += 4
                continue
            # 43 56 [상대 이동 u16]: 스톤헨지에서 확인된 특수 이벤트 분기.
            # 판정 기준은 미확인이지만 일반 상대 이동 형식과 동일하다.
            if i + 4 <= len(body) and body[i:i + 2] == b"\x43\x56":
                tokens.append({
                    "kind": "특수 분기", "raw": body[i:i + 4], "value": None,
                    "branch_opcode": 0x56, "editable": True,
                })
                i += 4
                continue
            # 43 2B 1C [상태값 u16] 1C [참조 상태값 u16] [상대 이동 u16]:
            # 두 런타임 상태값을 비교한다. 나마하게에서 확인된 형식이며, 뒤의
            # 상대 이동은 0x43 공통 분기 처리기가 읽는다. UI에서는 "상태값끼리 비교"로 표시한다.
            if i + 11 <= len(body) and body[i:i + 3] == b"\x43\x2B\x1C" and body[i + 5] == 0x1C:
                stat_id = struct.unpack_from("<H", body, i + 3)[0]
                source_stat_id = struct.unpack_from("<H", body, i + 6)[0]
                tokens.append({
                    "kind": STATE_REFERENCE_COMPARE_BRANCH_KIND, "raw": body[i:i + 11], "value": None,
                    "stat_id": stat_id, "source_stat_id": source_stat_id,
                    "branch_prefix": body[i:i + 9], "editable": True,
                })
                i += 11
                continue
            # 43 2B 1C [상태값 u16] 1A [기준값 u32] [상대 이동 u16]:
            # 악어 이벤트에서 확인된 고정 기준값 초과 분기다.
            if i + 12 <= len(body) and body[i:i + 3] == b"\x43\x2B\x1C" and body[i + 5] == 0x1A:
                stat_id = struct.unpack_from("<H", body, i + 3)[0]
                compare_value = struct.unpack_from("<I", body, i + 6)[0]
                tokens.append({
                    "kind": ABILITY_COMPARE3_BRANCH_KIND, "raw": body[i:i + 12], "value": None,
                    "stat_id": stat_id, "compare_value": compare_value,
                    "branch_prefix": body[i:i + 10], "editable": stat_id in STAT_TARGET_NAMES,
                })
                i += 12
                continue
            # 43 2E 1C [상태값 u16] <두 번째 피연산자> [상대 이동 u16]:
            # 2E 비교 연산의 피연산자는 1A(u32 상수) 또는 00(u16 상수)다.
            # 피연산자 길이가 달라서 고정 12바이트로 자르면 00 형식에서 다음
            # 대사 시작(00 0A)을 명령 안으로 잘못 포함한다.
            if i + 10 <= len(body) and body[i:i + 3] == b"\x43\x2E\x1C" and body[i + 5] in (0x00, 0x1A):
                stat_id = struct.unpack_from("<H", body, i + 3)[0]
                is_u32 = body[i + 5] == 0x1A
                length = 12 if is_u32 else 10
                if i + length <= len(body):
                    compare_value = struct.unpack_from("<I" if is_u32 else "<H", body, i + 6)[0]
                    relative_offset = 10 if is_u32 else 8
                    tokens.append({
                        "kind": STATE_SCALAR_COMPARE_BRANCH_KIND, "raw": body[i:i + length], "value": None,
                        "stat_id": stat_id, "compare_value": compare_value,
                        "branch_prefix": body[i:i + relative_offset], "relative_offset": relative_offset,
                        "editable": stat_id in STAT_TARGET_NAMES,
                    })
                    i += length
                    continue
            # 43 28 00 [상수 u16] 08 [런타임 객체 u16] [상대 이동 u16]:
            # 아즈텍왕국 전용으로 확인된 객체 참조 비교다. 0x28 처리기는 상수와
            # 객체 0x08을 차례로 읽어 객체의 런타임 값을 비교한다.
            if i + 10 <= len(body) and body[i:i + 3] == b"\x43\x28\0" and body[i + 5] == 0x08:
                threshold = struct.unpack_from("<H", body, i + 3)[0]
                runtime_id = struct.unpack_from("<H", body, i + 6)[0]
                tokens.append({
                    "kind": RUNTIME_REFERENCE_BRANCH_KIND, "raw": body[i:i + 10], "value": None,
                    "threshold": threshold, "runtime_id": runtime_id,
                    "branch_prefix": body[i:i + 8], "editable": True,
                })
                i += 10
                continue
            # 43 2B/2C/2D 1C [상태값 u16] 20 [폭 u32] [시작값 u32] [상대 이동 u16]:
            # 무작위 기준값과 상태값을 비교하고, 조건이 맞지 않으면 지정 행으로 이동한다.
            if i + 16 <= len(body) and body[i] == 0x43 and body[i + 1] in (0x2B, 0x2C, 0x2D) and body[i + 2] == 0x1C and body[i + 5] == 0x20:
                stat_id = struct.unpack_from("<H", body, i + 3)[0]
                width, first = struct.unpack_from("<II", body, i + 6)
                if width:
                    kind = {
                        0x2B: STATE_GREATER_RANDOM_BRANCH_KIND,
                        0x2C: STATE_LESS_RANDOM_BRANCH_KIND,
                        0x2D: STATE_LESS_OR_EQUAL_RANDOM_BRANCH_KIND,
                    }[body[i + 1]]
                    tokens.append({
                        "kind": kind, "raw": body[i:i + 16], "value": None,
                        "stat_id": stat_id, "compare_value": first,
                        "compare_value_text": f"{first}~{first + width - 1}",
                        "branch_prefix": body[i:i + 14], "editable": stat_id in STAT_TARGET_NAMES,
                    })
                    i += 16
                    continue
            # 43 2D 1C [상태값 u16] 1A [기준값 u32] [상대 이동 u16]:
            # 산 마르코 대성당에서 확인한 능력치 비교 분기. 명성 3,000/6,000을
            # 기준으로 입장 경로를 나누며, 1A는 수치 상수 표현이다.
            if i + 12 <= len(body) and body[i:i + 3] == b"\x43\x2D\x1C" and body[i + 5] == 0x1A:
                stat_id = struct.unpack_from("<H", body, i + 3)[0]
                compare_value = struct.unpack_from("<I", body, i + 6)[0]
                tokens.append({
                    "kind": ABILITY_COMPARE_BRANCH_KIND, "raw": body[i:i + 12], "value": None,
                    "stat_id": stat_id, "compare_value": compare_value,
                    "branch_prefix": body[i:i + 10], "editable": True,
                })
                i += 12
                continue
            # 43 2B 1C [상태값 u16] 14 [기준값 u32] [상대 이동 u16]:
            # 고정 기준값 초과 분기. 1A 형식과 구별되는 원본 표현을 보존한다.
            if i + 12 <= len(body) and body[i:i + 3] == b"\x43\x2B\x1C" and body[i + 5] == 0x14:
                stat_id = struct.unpack_from("<H", body, i + 3)[0]
                compare_value = struct.unpack_from("<I", body, i + 6)[0]
                tokens.append({
                    "kind": STATE_GREATER_BRANCH_KIND, "raw": body[i:i + 12], "value": None,
                    "stat_id": stat_id, "compare_value": compare_value,
                    "branch_prefix": body[i:i + 10], "editable": stat_id in STAT_TARGET_NAMES,
                })
                i += 12
                continue
            # 43 2C 1C 03 00 1A [금액 u32] [상대 이동 u16]:
            # 모뉴멘트밸리에서 확인된 소지금 비교 분기. 일반 상태값 비교의 14
            # 수식과 달리 1A 상수 형식을 사용하므로 별도 명령으로 기록한다.
            if i + 12 <= len(body) and body[i:i + 5] == b"\x43\x2C\x1C\x03\0" and body[i + 5] == 0x1A:
                amount = struct.unpack_from("<I", body, i + 6)[0]
                tokens.append({
                    "kind": "소지금 비교 분기", "raw": body[i:i + 12], "value": None,
                    "compare_value": amount, "branch_prefix": body[i:i + 10], "editable": True,
                })
                i += 12
                continue
            # 43 2C/2D 1C [상태값 u16] 14 [기준값 u32] [상대 이동 u16]: 상태값 미만/이하 조건 분기.
            if i + 12 <= len(body) and body[i] == 0x43 and body[i + 1] in (0x2C, 0x2D) and body[i + 2] == 0x1C and body[i + 5] == 0x14:
                stat_id = struct.unpack_from("<H", body, i + 3)[0]
                compare_value = struct.unpack_from("<I", body, i + 6)[0]
                tokens.append({
                    "kind": STATE_LESS_BRANCH_KIND if body[i + 1] == 0x2C else STATE_LESS_OR_EQUAL_BRANCH_KIND,
                    "raw": body[i:i + 12], "value": None,
                    "stat_id": stat_id, "compare_value": compare_value,
                    "branch_prefix": body[i:i + 10], "editable": stat_id in STAT_TARGET_NAMES,
                })
                i += 12
                continue
            # 43 11 0A [선택값 u8] [상대 이동 u16]: 다중 선택지의 선택값 분기.
            if i + 6 <= len(body) and body[i : i + 3] == b"\x43\x11\x0A":
                choice_value = body[i + 3]
                tokens.append({
                    "kind": CHOICE_BRANCH_KIND, "raw": body[i : i + 6], "value": None,
                    "choice_value": choice_value, "branch_prefix": body[i : i + 4], "editable": True,
                })
                i += 6
                continue
            # 19/1A 14 [u32]: 소지금을 지정한 금액만큼 증가/감소시킨다.
            if i + 6 <= len(body) and body[i:i + 2] in (b"\x19\x14", b"\x1A\x14"):
                kind = "소지금 증가" if body[i] == 0x19 else "소지금 감소"
                tokens.append({"kind": kind, "raw": body[i:i + 6], "value": struct.unpack_from("<I", body, i + 2)[0], "editable": True})
                i += 6
                continue
            # 32 1A [u32] 또는 32 20 [폭 u32][시작값 u32]: 날짜를 경과시킨다.
            if i + 6 <= len(body) and body[i:i + 2] == b"\x32\x1A":
                tokens.append({"kind": "날짜 경과", "raw": body[i:i + 6], "value": struct.unpack_from("<I", body, i + 2)[0], "editable": True})
                i += 6
                continue
            if i + 10 <= len(body) and body[i:i + 2] == b"\x32\x20":
                width, first = struct.unpack_from("<II", body, i + 2)
                if width:
                    tokens.append({
                        "kind": "날짜 경과", "raw": body[i:i + 10], "value": first,
                        "value_text": f"{first}~{first + width - 1}", "editable": True,
                    })
                else:
                    tokens.append({"kind": "미확인 명령/데이터", "raw": body[i:i + 10], "value": None, "editable": False})
                i += 10
                continue
            # 29 1A [u32]: 내부 시간 단위만큼 다음 명령을 지연한다.
            if i + 6 <= len(body) and body[i:i + 2] == b"\x29\x1A":
                tokens.append({"kind": "대기", "raw": body[i:i + 6], "value": struct.unpack_from("<I", body, i + 2)[0], "editable": True})
                i += 6
                continue
            if body[i] in (0x4C, 0x4D, 0x4E):
                tokens.append({
                    "kind": "이벤트 결과 코드",
                    "raw": body[i:i + 1],
                    "value": body[i] - 0x4C,
                    "editable": True,
                })
                i += 1
                continue
            if body[i] == 0x33:
                tokens.append({"kind": "이미지 표시 종료", "raw": b"\x33", "value": None, "editable": True})
                i += 1
                continue
            if body[i] == 0x48:
                tokens.append({"kind": "대화창 숨김", "raw": b"\x48", "value": None, "editable": True})
                i += 1
                continue
            if body[i] == 0x49:
                tokens.append({"kind": "대화창 표시", "raw": b"\x49", "value": None, "editable": True})
                i += 1
                continue
            if body[i] == 0x46:
                tokens.append({"kind": "결과 거짓 설정", "raw": b"\x46", "value": None, "editable": True})
                i += 1
                continue
            if body[i] == 0x4A:
                tokens.append({"kind": "결과 참 설정", "raw": b"\x4A", "value": None, "editable": True})
                i += 1
                continue
            # 31: 델포이 성지에서 주인공 성격을 판정·갱신한다.
            if body[i] == 0x31:
                tokens.append({"kind": "주인공 성격 판정", "raw": b"\x31", "value": None, "editable": True})
                i += 1
                continue
            # 19 1C [대상 u16] 1C [참조 상태값 u16]: 다른 상태값을 읽어 대상에 더한다.
            # 아마조네스·여러 민족 이벤트에서 공통으로 쓰이며, 뒤의 1C는 상수나
            # 무작위 수식이 아니라 런타임 상태값을 피연산자로 읽는 표식이다.
            if i + 7 <= len(body) and body[i : i + 2] == b"\x19\x1C" and body[i + 4] == 0x1C:
                stat_id = struct.unpack_from("<H", body, i + 2)[0]
                source_stat_id = struct.unpack_from("<H", body, i + 5)[0]
                tokens.append({
                    "kind": "상태값 참조 증가", "raw": body[i : i + 7],
                    "value": source_stat_id, "stat_id": stat_id,
                    "source_stat_id": source_stat_id,
                    "editable": stat_id in STAT_TARGET_NAMES,
                })
                i += 7
                continue
            # 19/1A/22/26 1C [대상 u16] 뒤에는 상수(1A u32) 또는
            # 무작위 범위(20 폭 u32 시작값 u32) 수식이 온다.
            # 대상 0·1만 능력치가 아니라 피로도·규율이므로, 번호를 숨기지 않고 별도 콤보로 편집한다.
            if (
                i + 9 <= len(body)
                and body[i] in (0x19, 0x1A, 0x22, 0x26)
                and body[i + 1] == 0x1C
                and body[i + 4] in (0x1A, 0x20)
            ):
                opcode = body[i]
                stat_id = struct.unpack_from("<H", body, i + 2)[0]
                random_range = body[i + 4] == 0x20
                if random_range and i + 13 > len(body):
                    tokens.append({"kind": "미확인 명령/데이터", "raw": body[i:i + 1], "value": None, "editable": False})
                    i += 1
                    continue
                raw_value = struct.unpack_from("<I", body, i + (9 if random_range else 5))[0]
                width = struct.unpack_from("<I", body, i + 5)[0] if random_range else 1
                kind = {
                    0x19: "상태값 증감",
                    0x1A: "상태값 증감",
                    0x22: "상태값 설정",
                    0x26: "상태값 설정",
                }[opcode]
                value = -raw_value if opcode == 0x1A else raw_value
                magnitude_end = raw_value + max(width - 1, 0)
                value_text = (
                    f"{-raw_value}~{-magnitude_end}" if opcode == 0x1A else f"{raw_value}~{magnitude_end}"
                ) if random_range else None
                tokens.append({
                    "kind": kind,
                    "raw": body[i:i + (13 if random_range else 9)],
                    "value": value,
                    "value_text": value_text,
                    "stat_id": stat_id,
                    "stat_opcode": opcode,
                    "editable": stat_id in STAT_TARGET_NAMES,
                })
                i += 13 if random_range else 9
                continue
            form = disev.form_at(body, i, len(body))
            if form is not None:
                raw = body[i:i + form.length]
                tokens.append({"kind": disev.describe_form(form, raw, i), "raw": raw, "value": None, "editable": False})
                i += form.length
                continue
            tokens.append({"kind": "미확인 명령/데이터", "raw": body[i:i + 1], "value": None, "editable": False})
            i += 1
        # 이벤트 바이트 주소 대신 편집기에서 보이는 명령 번호를 분기 값으로 쓴다.
        offsets: dict[int, int] = {}
        offset = 0
        for number, token in enumerate(tokens, 1):
            offsets[offset] = number
            offset += len(bytes(token["raw"]))
        branch_labels = {
            0x6D: "STORY0.CDS 외 분기",
            0x45: "결과 거짓 시 이동",
            0x47: "결과 참 시 이동",
            0x4B: "이전 조건 참 시 이동",
            0x56: "특수 분기",
            0x6E: "STORY1.CDS 외 분기",
        }
        offset = 0
        for token in tokens:
            raw = bytes(token["raw"])
            if token.get("kind") in (HINT_BRANCH_KIND, DISCOVERY_BRANCH_KIND, DISCOVERY_REGISTRATION_BRANCH_KIND, ITEM_POSSESSION_BRANCH_KIND, ITEM_ABSENCE_BRANCH_KIND, YEAR_BRANCH_KIND, YEAR_UPPER_BRANCH_KIND, YEAR_RANGE_BRANCH_KIND, CITY_BRANCH_KIND, NPC_BRANCH_KIND, CHOICE_BRANCH_KIND, STATE_REFERENCE_COMPARE_BRANCH_KIND, RUNTIME_REFERENCE_BRANCH_KIND, "소지금 비교 분기") + NUMERIC_COMPARE_BRANCH_KINDS:
                relative_offset = 14 if token.get("kind") in RANDOM_STATE_COMPARE_BRANCH_KINDS else 10 if token.get("kind") in (ABILITY_COMPARE_BRANCH_KIND, ABILITY_COMPARE3_BRANCH_KIND, STATE_GREATER_BRANCH_KIND, "소지금 비교 분기") else int(token.get("relative_offset", 9)) if token.get("kind") in (STATE_REFERENCE_COMPARE_BRANCH_KIND, STATE_SCALAR_COMPARE_BRANCH_KIND) else 8 if token.get("kind") == RUNTIME_REFERENCE_BRANCH_KIND else 8 if token.get("kind") == YEAR_RANGE_BRANCH_KIND else 4 if token.get("kind") == CHOICE_BRANCH_KIND else 5
                target_offset = offset + len(raw) + struct.unpack_from("<H", raw, relative_offset)[0]
                target_number = offsets.get(target_offset)
                token["target_index"] = target_number
                token["value"] = target_number
            elif len(raw) == 4 and raw[0] == 0x43 and raw[1] in branch_labels:
                target_offset = offset + len(raw) + struct.unpack_from("<H", raw, 2)[0]
                target_number = offsets.get(target_offset)
                if raw[1] in (0x6D, 0x6E):
                    # 이 둘은 본문 안의 상대 이동과 모양만 같고 실제로는 외부
                    # STORY 파일의 진입값을 사용한다. 우연히 본문 주소와 겹쳐도
                    # 내부 명령 번호로 바꾸지 않는다.
                    token["kind"] = branch_labels[raw[1]]
                    token["value"] = struct.unpack_from("<H", raw, 2)[0]
                    token["editable"] = True
                    token.pop("branch_opcode", None)
                    token.pop("target_index", None)
                    offset += len(raw)
                    continue
                token["branch_opcode"] = raw[1]
                token["target_index"] = target_number
                if target_number is not None:
                    token["kind"] = branch_labels[raw[1]]
                    token["value"] = target_number
                    token["editable"] = raw[1] in (0x45, 0x47, 0x4B, 0x56)
                else:
                    token["kind"] = branch_labels[raw[1]]
            offset += len(raw)
        return tokens

    def _shift_branch_targets_for_insert(self, insert_index: int) -> None:
        """행 삽입 뒤에도 기존 분기가 같은 명령을 가리키도록 행 번호를 보정한다."""
        for token in self.body_tokens:
            target = token.get("target_index")
            if isinstance(target, int) and target > insert_index:
                token["target_index"] = target + 1
                token["value"] = target + 1

    def _shift_branch_targets_for_remove(self, remove_index: int) -> None:
        """목적지 행을 지우면 해당 분기를 적용 전에 오류로 막는다."""
        removed_number = remove_index + 1
        for token in self.body_tokens:
            target = token.get("target_index")
            if not isinstance(target, int):
                continue
            if target == removed_number:
                token["target_index"] = None
                token["value"] = None
            elif target > removed_number:
                token["target_index"] = target - 1
                token["value"] = target - 1

    def _encode_body_tokens(self) -> bytes:
        """행 번호 기반 분기를 현재 본문 길이에 맞는 상대 바이트값으로 다시 기록한다."""
        offsets: list[int] = []
        offset = 0
        for token in self.body_tokens:
            offsets.append(offset)
            offset += len(bytes(token["raw"]))
        encoded: list[bytes] = []
        for index, token in enumerate(self.body_tokens):
            raw = bytes(token["raw"])
            opcode = token.get("branch_opcode")
            prefix = token.get("branch_prefix")
            if opcode is not None or isinstance(prefix, bytes):
                target = token.get("target_index")
                if not isinstance(target, int) or not 1 <= target <= len(offsets):
                    raise ValueError(f"{index + 1}번 분기의 이동할 행을 지정하세요.")
                header_size = len(prefix) + 2 if isinstance(prefix, bytes) else 4
                relative = offsets[target - 1] - (offsets[index] + header_size)
                if not 0 <= relative <= 65535:
                    raise ValueError(f"{index + 1}번 분기는 뒤쪽 행(현재 {index + 2}번 이후)만 지정할 수 있습니다.")
                raw = prefix + struct.pack("<H", relative) if isinstance(prefix, bytes) else b"\x43" + bytes((int(opcode),)) + struct.pack("<H", relative)
                token["raw"] = raw
                token["value"] = target
            encoded.append(raw)
        return b"".join(encoded)

    def _apply_body_command(self) -> None:
        if self.selected_body_index is None:
            return
        token = self.body_tokens[self.selected_body_index]
        if not bool(token["editable"]):
            return
        kind = self._builder_body_kind()
        if kind not in BODY_COMMAND_KINDS:
            return
        try:
            if kind in DIALOGUE_KINDS:
                text = self.body_value_var.get()
                encoded = (
                    encode_multichoice_dialogue_text(text)
                    if kind == "다중 선택지 대사"
                    else encode_dialogue_text(text)
                )
                if b"\0" in encoded:
                    raise ValueError("대사에는 NUL 문자를 넣을 수 없습니다.")
                # 일반 대사는 반드시 00 0A ... 00 형식으로 정규화한다.
                # 과거 버전이 저장한 0A ... 00(창 플래그 누락) 형식은 게임이
                # 본문 명령으로 처리하지 못할 수 있으므로 보존하면 안 된다.
                # 선택지 플래그(0B/10)만 일반 대사로 해제한다.
                old_flag = token.get("flag")
                if kind == "대상 지정 대사":
                    updated = self._new_body_token(
                        kind, text, character_id=self._body_npc_id(),
                        speaker_prefix=self._body_speaker_prefix(),
                    )
                    token.update(updated)
                    self.pending = True
                    self._refresh_body_list_selection()
                    self.status_var.set(ui("status_body_updated"))
                    return
                flag = 0x0B if kind == "예/아니오 대사" else (old_flag if kind == "다중 선택지 대사" and old_flag in (0x10, 0x18) else 0x10 if kind == "다중 선택지 대사" else 0x00)
                speaker_prefix = self._body_speaker_prefix()
                suffix = b"\0" + bytes((int(token.get("choice_count", 0)),)) if kind == "다중 선택지 대사" else b"\0"
                token["raw"] = bytes((int(flag), 0x0A)) + speaker_prefix + encoded + suffix
                token["value"] = text
                token["speaker_prefix"] = speaker_prefix
                token["flag"] = flag
                token["kind"] = kind
            elif kind == "발견물 이름 설정":
                updated = self._new_body_token(
                    kind,
                    self.body_value_var.get(),
                    self._body_character_id(),
                    dialogue_layout=str(token.get("dialogue_layout", "text_first")),
                    speaker_prefix=bytes(token.get("speaker_prefix", b"")),
                )
                token.update(updated)
            elif kind in STAT_COMMAND_KINDS:
                updated = self._new_body_token(kind, self._body_input_value(kind), stat_id=self._body_stat_id())
                # 22 1C 형식으로 읽어 온 설정 명령은 편집해도 그 형식을 보존한다.
                if kind == "상태값 설정" and token.get("stat_opcode") == 0x22:
                    raw = bytearray(updated["raw"])
                    raw[0] = 0x22
                    updated["raw"] = bytes(raw)
                    updated["stat_opcode"] = 0x22
                token.update(updated)
            elif kind in STAT_REFERENCE_COMMAND_KINDS:
                token.update(self._new_body_token(
                    kind, stat_id=self._body_stat_id(),
                    compare_value=int(self.body_value_var.get().strip()),
                ))
            elif kind in ("아이템 획득", "아이템 상실", "이벤트 아이템 등록", "이벤트 아이템 처리"):
                token.update(self._new_body_token(kind, self._body_input_value(kind)))
            elif kind == "힌트 획득":
                token.update(self._new_body_token(kind, hint_id=self._body_hint_id()))
            elif kind in ("신도시 생성", "발견물 등록/발견 처리"):
                token.update(self._new_body_token(kind, self._body_input_value(kind)))
            elif kind == "특수 조우 연출 설정":
                token.update(self._new_body_token(kind, self._body_input_value(kind)))
            elif kind == "해상 전투":
                token.update(self._new_body_token(kind, self._body_input_value(kind)))
            elif kind in ("인물 이벤트 실행", "인물 이벤트 실행 (보조)"):
                token.update(self._new_body_token(kind, self._body_input_value(kind)))
            elif kind in CHARACTER_TARGET_COMMAND_KINDS:
                token.update(self._new_body_token(kind, self._body_input_value(kind), character_id=self._body_npc_id()))
            elif kind == "이벤트 내부 참조":
                token.update(self._new_body_token(kind, self._body_input_value(kind)))
            elif kind == "이벤트 분류 설정":
                token.update(self._new_body_token(kind, self._body_input_value(kind)))
            elif kind == "이벤트 조건 판정":
                token.update(self._new_body_token(kind, self._body_input_value(kind)))
            elif kind == "특수 수치 판정":
                token.update(self._new_body_token(kind, self.special_check_value_var.get(), compare_value=self.special_difficulty_var.get()))
            elif kind in ("STORY0.CDS 외 분기", "STORY1.CDS 외 분기"):
                token.update(self._new_body_token(kind, self.body_value_var.get()))
            elif kind in ("결과 거짓 시 이동", "결과 참 시 이동", "이전 조건 참 시 이동", "특수 분기", "소지금 비교 분기", RUNTIME_REFERENCE_BRANCH_KIND, CHOICE_BRANCH_KIND, HINT_BRANCH_KIND, DISCOVERY_BRANCH_KIND, DISCOVERY_REGISTRATION_BRANCH_KIND, ITEM_POSSESSION_BRANCH_KIND, ITEM_ABSENCE_BRANCH_KIND, YEAR_BRANCH_KIND, YEAR_UPPER_BRANCH_KIND, YEAR_RANGE_BRANCH_KIND, CITY_BRANCH_KIND, NPC_BRANCH_KIND, STATE_REFERENCE_COMPARE_BRANCH_KIND) + NUMERIC_COMPARE_BRANCH_KINDS:
                target_index = int(self.body_value_var.get().strip())
                if not 1 <= target_index <= len(self.body_tokens):
                    raise ValueError(f"이동할 행은 1~{len(self.body_tokens)} 범위여야 합니다.")
                if target_index <= self.selected_body_index + 1:
                    raise ValueError("이동할 행은 현재 행보다 뒤에 있어야 합니다.")
                preserve_u16_scalar = (
                    kind == STATE_SCALAR_COMPARE_BRANCH_KIND
                    and bytes(token.get("raw", b""))[5:6] == b"\x00"
                )
                updated = self._new_body_token(
                    kind, str(target_index), hint_id=self._body_hint_id() if kind == HINT_BRANCH_KIND else None,
                    item_id=self._body_item_id() if kind in (ITEM_POSSESSION_BRANCH_KIND, ITEM_ABSENCE_BRANCH_KIND) else None,
                    hint_active=self.body_hint_state_var.get() == "활성",
                    character_id=self._body_character_id() if kind in (DISCOVERY_BRANCH_KIND, DISCOVERY_REGISTRATION_BRANCH_KIND) else self._body_city_id() if kind == CITY_BRANCH_KIND else self._body_npc_id(self.sponsor_targets if self.body_detail_var.get() == "후원자" else self.character_targets) if kind == NPC_BRANCH_KIND else int(self.body_range_end_var.get().strip()) if kind == RUNTIME_REFERENCE_BRANCH_KIND else None,
                    npc_type=0x12 if kind == NPC_BRANCH_KIND and self.body_detail_var.get() == "후원자" else 0x0D,
                    stat_id=self._body_stat_id() if kind in NUMERIC_COMPARE_BRANCH_KINDS + (STATE_REFERENCE_COMPARE_BRANCH_KIND,) else None,
                    compare_value=f"{self.body_value2_var.get().strip()}~{self.body_range_end_var.get().strip()}" if kind == YEAR_RANGE_BRANCH_KIND else self.body_value2_var.get().strip() if kind in RANDOM_STATE_COMPARE_BRANCH_KINDS + (YEAR_BRANCH_KIND, YEAR_UPPER_BRANCH_KIND) else int(self.body_value2_var.get().strip()) if kind in NUMERIC_COMPARE_BRANCH_KINDS + (STATE_REFERENCE_COMPARE_BRANCH_KIND, "소지금 비교 분기", RUNTIME_REFERENCE_BRANCH_KIND) else None,
                    choice_value=int(self.body_value2_var.get().strip()) if kind == CHOICE_BRANCH_KIND else None,
                )
                # 잉카제국의 16번 명령은 43 2E 1C + 상태값 + 00[u16] 형식이다.
                # 일반 생성기는 1A[u32]를 쓰므로, 기존 16비트 상수 표현을 편집
                # 뒤에도 보존한다. 16비트 범위를 넘는 값은 원본 형식을 유지할 수 없다.
                if preserve_u16_scalar:
                    threshold = int(self.body_value2_var.get().strip())
                    if not 0 <= threshold <= 0xFFFF:
                        raise ValueError("이 명령의 기준값은 원본 16비트 형식이므로 0~65,535 범위여야 합니다.")
                    prefix = b"\x43\x2E\x1C" + struct.pack("<H", self._body_stat_id()) + b"\x00" + struct.pack("<H", threshold)
                    updated["raw"] = prefix + b"\0\0"
                    updated["branch_prefix"] = prefix
                    updated["relative_offset"] = 8
                token.update(updated)
            elif kind in ("이미지 표시 종료", "대화창 숨김", "대화창 표시", "결과 거짓 설정", "결과 참 설정", "주인공 성격 판정"):
                token.update(self._new_body_token(kind))
            elif kind == "이벤트 결과 코드":
                token.update(self._new_body_token(kind, str(self._body_result_code())))
            elif kind == "대기":
                token.update(self._new_body_token(kind, self.body_value_var.get()))
            elif kind == "날짜 경과":
                token.update(self._new_body_token(kind, self._body_input_value(kind)))
            elif kind in ("소지금 증가", "소지금 감소", "이벤트 플래그 설정", "내부 상태 설정", "특수 상태 처리"):
                token.update(self._new_body_token(kind, self.body_value_var.get()))
            else:
                value = int(self.body_value_var.get().strip())
                maximum = 15 if kind == "EVSTILL 이미지 표시" else 65535
                if not 0 <= value <= maximum:
                    raise ValueError(f"값은 0~{maximum} 범위여야 합니다.")
                token["raw"] = self._new_body_token(kind)["raw"]
                raw = bytearray(token["raw"])
                struct.pack_into("<H", raw, 2, value)
                token["raw"] = bytes(raw)
                token["value"] = value
                token["kind"] = kind
        except (UnicodeEncodeError, ValueError) as exc:
            messagebox.showerror(ui("body_edit_failed"), str(exc), parent=self.root)
            return
        self.pending = True
        self._refresh_body_list_selection()
        self.status_var.set(ui("status_body_updated"))

    def _refresh_body_list_selection(self) -> None:
        selected = self.selected_body_index
        self.body_tree.delete(*self.body_tree.get_children())
        for index, token in enumerate(self.body_tokens):
            if token["kind"] == "본문 끝":
                continue
            self.body_tree.insert(
                "", "end", iid=str(index),
                values=(index + 1, *self._body_display_levels(token), self._body_display_value(token)),
            )
        if selected is not None and self.body_tree.exists(str(selected)):
            self.body_tree.selection_set(str(selected))
            self.body_tree.focus(str(selected))
        self.root.after_idle(lambda: self._autosize_tree_columns(self.body_tree, skip=("value",)))

    def _body_display_levels(self, token: dict[str, object]) -> tuple[str, str, str, str]:
        """본문 목록의 명령 분류를 최대 4개 열로 나눠 표시한다."""
        kind = str(token["kind"])
        group, subkind = BODY_KIND_TO_GROUP.get(kind, (kind, ""))
        detail = BODY_KIND_TO_DETAIL.get(kind, "")
        fourth = ""
        if kind in DIALOGUE_KINDS:
            prefix = bytes(token.get("speaker_prefix", b""))
            detail = next((name for name, value in self.dialogue_speakers.items() if value == prefix), "화자 미확인")
        elif kind in STAT_COMMAND_KINDS:
            detail = STAT_TARGET_NAMES.get(int(token.get("stat_id", -1)), "대상 미확인")
        elif kind == HINT_BRANCH_KIND:
            detail = "활성" if token.get("hint_active", True) else "미활성"
            hint_id = int(token.get("hint_id", -1))
            fourth = next((name for candidate_id, name in self.hint_targets if candidate_id == hint_id), f"힌트 {hint_id}")
        elif kind == DISCOVERY_BRANCH_KIND:
            discovery_id = int(token.get("character_id", -1))
            fourth = next((name for candidate_id, name in self.discovery_targets if candidate_id == discovery_id), f"발견물 {discovery_id}")
        elif kind == DISCOVERY_REGISTRATION_BRANCH_KIND:
            discovery_id = int(token.get("character_id", -1))
            fourth = next((name for candidate_id, name in self.discovery_targets if candidate_id == discovery_id), f"발견물 {discovery_id}")
        elif kind == CITY_BRANCH_KIND:
            city_id = int(token.get("character_id", -1))
            detail = next((name for candidate_id, name in self.city_targets if candidate_id == city_id), f"도시 {city_id}")
        elif kind == NPC_BRANCH_KIND:
            npc_type = int(token.get("npc_type", 0x0D)); detail = "후원자" if npc_type == 0x12 else "인물"
            targets = self.sponsor_targets if npc_type == 0x12 else self.character_targets
            npc_id = int(token.get("character_id", -1))
            fourth = next((name for candidate_id, name in targets if candidate_id == npc_id), f"NPC {npc_id}")
        elif kind in (ITEM_POSSESSION_BRANCH_KIND, ITEM_ABSENCE_BRANCH_KIND):
            item_id = int(token.get("item_id", -1))
            fourth = next((name for candidate_id, name in self.item_targets if candidate_id == item_id), f"아이템 {item_id}")
        elif kind in NUMERIC_COMPARE_BRANCH_KINDS:
            fourth = STAT_TARGET_NAMES.get(int(token.get("stat_id", -1)), "대상 미확인")
        elif kind == STATE_REFERENCE_COMPARE_BRANCH_KIND:
            detail = "상태값끼리 비교"
            target_name = STAT_TARGET_NAMES.get(int(token.get("stat_id", -1)), f"상태값 {token.get('stat_id', '?')}")
            source_name = STAT_TARGET_NAMES.get(int(token.get("source_stat_id", -1)), f"상태값 {token.get('source_stat_id', '?')}")
            fourth = f"{target_name} / {source_name}"
        elif kind in STAT_REFERENCE_COMMAND_KINDS:
            detail = STAT_TARGET_NAMES.get(int(token.get("stat_id", -1)), "대상 미확인")
        return str(group), str(subkind), str(detail), str(fourth)

    def _body_display_value(self, token: dict[str, object]) -> str:
        """본문 목록에서는 참조 ID 대신 사람이 읽을 수 있는 이름을 보여 준다."""
        value_text = token.get("value_text")
        if value_text is not None:
            return str(value_text)
        value = token.get("value")
        if value is None:
            return "-"
        kind = str(token["kind"])
        target_sets: dict[str, list[tuple[int, str]]] = {
            "아이템 획득": self.item_targets,
            "아이템 상실": self.item_targets,
            "이벤트 아이템 등록": self.item_targets,
            "이벤트 아이템 처리": self.item_targets,
            "신도시 생성": self.city_targets,
            "발견물 등록/발견 처리": self.discovery_targets,
            "힌트 획득": self.hint_targets,
            "인물 상태 처리 1": self.character_targets,
            "인물 상태 처리 2": self.character_targets,
            "인물 상태 처리 3": self.character_targets,
            "인물 참조 설정": self.character_targets,
            "인물 상태 처리 4": self.character_targets,
            "인물 상태 비트 해제": self.character_targets,
            "인물 선택 판정": self.character_targets,
            "인물 위치 판정": self.character_targets,
        }
        for target_id, name in target_sets.get(kind, []):
            if target_id == value:
                return name
        if kind == "이벤트 결과 코드":
            return EVENT_RESULT_NAMES.get(int(value), f"알 수 없는 결과 ({value})")
        if kind in STAT_REFERENCE_COMMAND_KINDS:
            return STAT_TARGET_NAMES.get(int(value), f"상태값 ID {value}")
        return str(value)

    def _set_readonly(self, widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _apply_editor(self) -> bool:
        if self.current_index is None:
            return True
        index = self.current_index
        old = self.parts[index]
        try:
            step, slots = disev.validate_part(old, index)
            if len(slots) != 1:
                raise ValueError("현재 버전은 슬롯 1개인 파트만 편집할 수 있습니다.")
            condition_start, body_start = slots[0]
            condition = self._encode_condition_tokens()
            body = self._encode_body_tokens()
            changed = bytearray(old[:condition_start] + condition + body)
            struct.pack_into("<H", changed, 6, condition_start + len(condition) - 4)
            changed_bytes = bytes(changed)
            disev.validate_part(changed_bytes, index)
        except (ValueError, struct.error) as exc:
            messagebox.showerror(ui("apply_failed"), str(exc), parent=self.root)
            return False

        self.parts[index] = changed_bytes
        if changed_bytes == self.original_parts[index]:
            self.modified.discard(index)
        else:
            self.modified.add(index)
        self.pending = False
        self._load_part(index)
        self._refresh_tree(keep_index=index)
        self._update_dirty_status()
        self.status_var.set(ui("status_applied", index))
        return True

    def _revert_part(self) -> None:
        if self.current_index is None:
            return
        index = self.current_index
        self.parts[index] = self.original_parts[index]
        self.modified.discard(index)
        self.pending = False
        self._load_part(index)
        self._refresh_tree(keep_index=index)
        self._update_dirty_status()
        self.status_var.set(ui("status_reverted", index))

    def _update_dirty_status(self) -> None:
        self.dirty_var.set(f"수정된 파트: {len(self.modified)}개" if self.modified else "")

    def _save(self) -> None:
        if self.disev_path is None:
            return
        self._write_archive(self.disev_path, make_backup=True)

    def _write_archive(self, target: Path, make_backup: bool) -> None:
        if self.pending and not self._apply_editor():
            return
        if not self.parts:
            return
        try:
            rebuilt = rebuild_archive(self.archive, self.entries, self.parts, self.modified)
            verify_archive(rebuilt, self.parts)
            backup_path: Path | None = None
            if make_backup and target.exists():
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                # 원본 확장자를 유지해 바로 열 수 있도록
                # DISEV_20260830_183015.CDS 형식으로 저장한다.
                backup_path = target.with_name(f"{target.stem}_{stamp}{target.suffix}")
                shutil.copy2(target, backup_path)
            temporary = target.with_name(target.name + ".disev_editor.tmp")
            temporary.write_bytes(rebuilt)
            temporary.replace(target)
        except (OSError, ValueError, struct.error) as exc:
            messagebox.showerror(ui("save_failed"), str(exc), parent=self.root)
            return

        self.disev_path = target.resolve()
        self.archive = rebuilt
        self.entries = disev.parse_archive(rebuilt)
        self.original_parts = list(self.parts)
        self.modified.clear()
        self._refresh_tree(keep_index=self.current_index)
        self._update_dirty_status()
        backup_message = ui("backup_message", backup_path.name) if backup_path else ""
        messagebox.showinfo(
            ui("save_complete"),
            ui("save_complete_message", backup_message),
            parent=self.root,
        )
        self.status_var.set(ui("status_saved", self.disev_path))

    def _confirm_abandon_archive(self) -> bool:
        if not self.modified and not self.pending:
            return True
        return messagebox.askyesno(
            ui("unsaved_changes"),
            ui("discard_changes_prompt"),
            parent=self.root,
        )

    @staticmethod
    def _release_asset(release: object) -> dict[str, object] | None:
        """Release 자산에서 이 편집기 버전의 ZIP을 찾는다."""
        if not isinstance(release, dict):
            return None
        version = str(release.get("tag_name", "")).strip().lstrip("vV")
        expected = UPDATE_ASSET_NAME.format(version=version) if version else UPDATE_ASSET_NAME
        for asset in release.get("assets", []):
            if isinstance(asset, dict) and asset.get("name") == expected:
                return asset
        return next((asset for asset in release.get("assets", [])
                     if isinstance(asset, dict) and str(asset.get("name", "")).lower().endswith(".zip")), None)

    @staticmethod
    def _extract_update_executable(archive_path: str) -> str:
        """업데이트 ZIP에서 단일 DISEV EXE만 임시 폴더에 안전하게 푼다."""
        extract_directory = tempfile.mkdtemp(prefix="DISEV_Editor_update_")
        try:
            with zipfile.ZipFile(archive_path) as archive:
                candidates = [entry for entry in archive.infolist()
                              if not entry.is_dir()
                              and os.path.basename(entry.filename).lower() == UPDATE_EXECUTABLE_NAME.lower()]
                if len(candidates) != 1:
                    raise ValueError(ui("update_zip_executable_count"))
                entry = candidates[0]
                destination = os.path.abspath(os.path.join(extract_directory, entry.filename))
                if os.path.commonpath((extract_directory, destination)) != extract_directory:
                    raise ValueError(ui("update_zip_path_invalid"))
                archive.extract(entry, extract_directory)
            if not os.path.isfile(destination):
                raise ValueError(ui("update_zip_extract_failed"))
            return destination
        except (OSError, ValueError, zipfile.BadZipFile):
            shutil.rmtree(extract_directory, ignore_errors=True)
            raise

    @staticmethod
    def _consume_update_notice() -> tuple[str, str] | None:
        """교체 뒤 새 EXE에 전달된 일회용 업데이트 알림을 읽는다."""
        try:
            marker = sys.argv.index("--update-notice")
            notice_path = sys.argv[marker + 1]
        except (ValueError, IndexError):
            return None
        try:
            with open(notice_path, "r", encoding="utf-8") as notice_file:
                notice = json.load(notice_file)
        except (OSError, ValueError):
            return None
        finally:
            try:
                if "notice_path" in locals() and os.path.isfile(notice_path):
                    os.remove(notice_path)
            except OSError:
                pass
        if not isinstance(notice, dict):
            return None
        version = str(notice.get("version", "")).strip()
        if parse_release_version(version) != parse_release_version(APP_VERSION):
            return None
        return version, str(notice.get("notes", "")).strip()

    @staticmethod
    def _format_update_history(releases: object) -> str:
        """정식 Release 이력을 최신 버전부터 읽기용 텍스트로 만든다."""
        history: list[tuple[tuple[int, int, int], str, str]] = []
        if not isinstance(releases, list):
            return ""
        for release in releases:
            if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
                continue
            tag = str(release.get("tag_name", "")).strip().lstrip("vV")
            version = parse_release_version(tag)
            if version is None or version < UPDATE_HISTORY_MIN_VERSION:
                continue
            notes = str(release.get("body", "")).strip() or ui("update_history_empty")
            history.append((version, tag, notes))
        history.sort(key=lambda row: row[0], reverse=True)
        return "\n\n".join(f"v{tag}\n{notes}" for _version, tag, notes in history)

    def _show_update_history_dialog(self, version: str, history: str) -> None:
        """업데이트 뒤 전체 이력을 스크롤 가능한 중앙 팝업으로 보여 준다."""
        self.root.update_idletasks()
        dialog = tk.Toplevel(self.root)
        dialog.title(APP_TITLE)
        dialog.transient(self.root)
        dialog.resizable(True, True)
        width, height = 620, 460
        x = self.root.winfo_x() + max(0, (self.root.winfo_width() - width) // 2)
        y = self.root.winfo_y() + max(0, (self.root.winfo_height() - height) // 2)
        dialog.geometry(f"{width}x{height}+{x}+{y}")
        dialog.minsize(440, 260)
        ttk.Label(dialog, text=ui("update_history_title", version), font=("Malgun Gothic", 10, "bold")).pack(
            anchor="w", padx=12, pady=(12, 6))
        host = ttk.Frame(dialog)
        host.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        scrollbar = ttk.Scrollbar(host, orient="vertical")
        text = tk.Text(host, wrap="word", font=("Malgun Gothic", 9), yscrollcommand=scrollbar.set,
                       padx=8, pady=7, relief="solid", borderwidth=1)
        scrollbar.configure(command=text.yview)
        text.insert("1.0", history or ui("update_history_empty"))
        text.configure(state="disabled")
        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        ttk.Button(dialog, text=ui("close"), command=dialog.destroy).pack(pady=(0, 12))
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.focus_set()

    def _show_update_notice(self) -> None:
        if self._update_notice is None:
            return
        version, notes = self._update_notice
        self._update_notice = None

        def worker() -> None:
            history = f"v{version}\n{notes or ui('update_history_empty')}"
            try:
                request = Request(UPDATE_RELEASES_URL, headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": f"DISEV-Editor/{APP_VERSION}",
                })
                with urlopen(request, timeout=8) as response:
                    history = self._format_update_history(json.loads(response.read().decode("utf-8")))
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
                pass
            try:
                self.root.after(0, lambda: self._show_update_history_dialog(version, history))
            except tk.TclError:
                pass

        threading.Thread(target=worker, name="disev-update-history", daemon=True).start()

    def _show_update_button(self, visible: bool) -> None:
        if visible:
            if not self.update_button.winfo_manager():
                self.update_button.pack(side="left", padx=(6, 0))
        else:
            self.update_button.pack_forget()

    def check_for_updates(self, automatic: bool = False) -> None:
        """GitHub 최신 정식 Release를 백그라운드에서 확인한다."""
        if self._update_check_in_progress or self._update_download_in_progress or not UPDATE_LATEST_URL:
            return
        self._update_check_in_progress = True
        self.update_button.configure(state="disabled")
        if not automatic:
            self.status_var.set(ui("checking_updates"))

        def worker() -> None:
            try:
                request = Request(UPDATE_LATEST_URL, headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": f"DISEV-Editor/{APP_VERSION}",
                })
                with urlopen(request, timeout=8) as response:
                    release = json.loads(response.read().decode("utf-8"))
                try:
                    self.root.after(0, lambda: self._handle_update_release(release, automatic))
                except tk.TclError:
                    pass
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
                try:
                    self.root.after(0, lambda: self._handle_update_error(error, automatic))
                except tk.TclError:
                    pass

        threading.Thread(target=worker, name="disev-update-check", daemon=True).start()

    def _handle_update_error(self, error: object, automatic: bool) -> None:
        self._update_check_in_progress = False
        self.update_button.configure(state="normal")
        if not automatic:
            messagebox.showwarning(APP_TITLE, ui("update_check_failed", error), parent=self.root)

    def _handle_update_release(self, release: object, automatic: bool) -> None:
        self._update_check_in_progress = False
        self.update_button.configure(state="normal")
        if not isinstance(release, dict):
            self._handle_update_error("invalid release response", automatic)
            return
        remote_tag = str(release.get("tag_name", "")).strip()
        remote_version = parse_release_version(remote_tag)
        if remote_version is None or remote_version <= parse_release_version(APP_VERSION):
            if not automatic:
                messagebox.showinfo(APP_TITLE, ui("latest_version", APP_VERSION), parent=self.root)
            return
        asset = self._release_asset(release)
        if asset is None or not asset.get("browser_download_url"):
            if not automatic:
                messagebox.showwarning(APP_TITLE, ui("update_asset_missing"), parent=self.root)
            return
        self._show_update_button(True)
        if automatic:
            return
        if messagebox.askyesno(APP_TITLE, ui("update_available", remote_tag.lstrip("vV"), APP_VERSION), parent=self.root):
            if self._confirm_abandon_archive():
                self._download_and_install_update(asset, release)

    def _download_and_install_update(self, asset: dict[str, object], release: dict[str, object]) -> None:
        if not getattr(sys, "frozen", False):
            messagebox.showinfo(APP_TITLE, ui("update_only_frozen"), parent=self.root)
            return
        self._update_download_in_progress = True
        self.update_button.configure(state="disabled")
        self.status_var.set(ui("downloading_update"))

        def worker() -> None:
            partial_path = ""
            download_path = ""
            try:
                asset_name = os.path.basename(str(asset.get("name", UPDATE_ASSET_NAME))) or UPDATE_ASSET_NAME
                partial_path = os.path.join(tempfile.gettempdir(), f"{asset_name}.{os.getpid()}.part")
                download_path = partial_path[:-5]
                digest = hashlib.sha256()
                request = Request(str(asset["browser_download_url"]), headers={
                    "Accept": "application/octet-stream", "User-Agent": f"DISEV-Editor/{APP_VERSION}",
                })
                with urlopen(request, timeout=30) as response, open(partial_path, "wb") as output:
                    for chunk in iter(lambda: response.read(1024 * 1024), b""):
                        output.write(chunk)
                        digest.update(chunk)
                expected = str(asset.get("digest", ""))
                if expected.startswith("sha256:") and digest.hexdigest().lower() != expected[7:].lower():
                    raise ValueError(ui("update_digest_failed"))
                os.replace(partial_path, download_path)
                executable = self._extract_update_executable(download_path)
                os.remove(download_path)
                try:
                    self.root.after(0, lambda: self._launch_update_replacer(executable, release))
                except tk.TclError:
                    pass
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, zipfile.BadZipFile) as error:
                for path in (partial_path, download_path):
                    try:
                        if path and os.path.isfile(path):
                            os.remove(path)
                    except OSError:
                        pass
                try:
                    self.root.after(0, lambda: self._handle_update_download_error(error))
                except tk.TclError:
                    pass

        threading.Thread(target=worker, name="disev-update-download", daemon=True).start()

    def _handle_update_download_error(self, error: object) -> None:
        self._update_download_in_progress = False
        self.update_button.configure(state="normal")
        messagebox.showerror(APP_TITLE, ui("update_failed", error), parent=self.root)

    def _launch_update_replacer(self, source_path: str, release: dict[str, object]) -> None:
        """현재 EXE 종료 후 교체·재시작하는 일회용 배치 파일을 실행한다."""
        if not self._confirm_abandon_archive():
            self._update_download_in_progress = False
            self.update_button.configure(state="normal")
            return
        target_path = os.path.abspath(sys.executable)
        script_path = os.path.join(tempfile.gettempdir(), f"DISEV_Editor_update_{os.getpid()}.cmd")
        notice_path = os.path.join(tempfile.gettempdir(), f"DISEV_Editor_update_notice_{os.getpid()}.json")
        try:
            with open(notice_path, "w", encoding="utf-8") as output:
                json.dump({"version": str(release.get("tag_name", "")).lstrip("vV"),
                           "notes": str(release.get("body", "")).strip()}, output, ensure_ascii=False)
            script = "\r\n".join((
                "@echo off", "setlocal",
                f'set "UPDATE_SOURCE={source_path}"', f'set "UPDATE_TARGET={target_path}"',
                f'set "UPDATE_NOTICE={notice_path}"', f'set "UPDATE_DIRECTORY={os.path.dirname(source_path)}"',
                ":replace_editor", 'move /Y "%UPDATE_SOURCE%" "%UPDATE_TARGET%" >nul 2>nul',
                "if errorlevel 1 (", "  timeout /t 1 /nobreak >nul", "  goto replace_editor", ")",
                'set "PYINSTALLER_RESET_ENVIRONMENT=1"',
                'start "" "%UPDATE_TARGET%" --update-notice "%UPDATE_NOTICE%"',
                'rmdir "%UPDATE_DIRECTORY%" 2>nul', 'del "%~f0"',
            ))
            with open(script_path, "w", encoding="mbcs", newline="") as output:
                output.write(script)
            flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.Popen(["cmd.exe", "/d", "/c", script_path], close_fds=True, creationflags=flags)
        except OSError as error:
            self._handle_update_download_error(error)
            return
        self.status_var.set(ui("update_restarting"))
        self.root.after(100, self.root.destroy)

    def _close(self) -> None:
        if self.modified or self.pending:
            answer = messagebox.askyesnocancel(
                ui("exit"),
                ui("save_before_exit_prompt"),
                parent=self.root,
            )
            if answer is None:
                return
            if answer:
                if self.disev_path is None:
                    return
                before = bool(self.modified or self.pending)
                self._write_archive(self.disev_path, make_backup=True)
                if before and (self.modified or self.pending):
                    return
        self.search_edit.destroy()
        self.root.destroy()


def main() -> int:
    root = tk.Tk()
    DisevEditor(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
