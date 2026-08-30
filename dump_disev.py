#!/usr/bin/env python3
"""Decode DISEV.CDS and write a lossless, annotated text dump.

The semantic names in this file are deliberately conservative.  Bytes whose
meaning has not been demonstrated are printed as ``미확인`` and every decoded
part is followed by a complete hexadecimal dump, so no script data is lost
even when an opcode is not known yet.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from insert_discovery_still import (
    AVI_OFFSET,
    CG_OFFSET,
    NO_MEDIA,
    RECORD_SIZE,
    STILL_OFFSET,
    discovery_table,
    locate_discovery_record,
    u32,
    va_to_file_offset,
)


CATEGORY_NAMES = {
    0: "지리",
    1: "역사",
    2: "보물",
    3: "종교",
    4: "교역품",
    5: "미신",
    6: "생물",
    7: "민족",
}

STAT_NAMES = {
    0: "피로도",
    1: "규율",
    2: "총 선원 수",
    3: "소지금",
    4: "악명",
    6: "무력",
    7: "체력",
    8: "생명력",
    10: "동승 인물 체력",
    11: "동승 인물 생명력",
    17: "명성",
    18: "운",
    20: "현재 함선 내구도",
    21: "지력",
    22: "매력",
    23: "신앙심",
}

# Dialogue speaker tags are retained in the original Japanese CP932 even in
# the Korean release.  The 0x81 0x46 full-width colon terminates the tag.
SPEAKER_NAMES = {
    # EXE의 한국어 인물명 표에서 같은 순서의 일본어 이름 `ムー人`은
    # `무어인`으로 대응한다.
    bytes.fromhex("83 80 81 5B 90 6C"): "무어인",
    bytes.fromhex("83 4D 83 8B 83 68"): "조합",
    bytes.fromhex("8B B3 89 EF"): "교회",
    bytes.fromhex("95 9B 8A AF"): "부관",
    bytes.fromhex("8C F0 88 D5 8F 8A"): "교역소",
    bytes.fromhex("83 7D 83 6B 83 47 83 8B 88 EA 90 A2"): "마누엘 1세",
    bytes.fromhex("8F E9 96 E5"): "성문",
    bytes.fromhex("8E B7 8E 96"): "집사",
    bytes.fromhex("8E F0 8F EA"): "술집",
    bytes.fromhex("83 84 83 52 83 76 81 81 83 74 83 62 83 4B 81 5B"): "야코프 푸거",
    bytes.fromhex("96 BA"): "딸",
    bytes.fromhex("83 4A 83 8B 83 8D 83 58 88 EA 90 A2"): "카를로스 1세",
    bytes.fromhex("89 C3 96 F5 92 E9"): "가정제",
    bytes.fromhex("83 8C 83 49 8F 5C 90 A2"): "레오 10세",
    bytes.fromhex("83 57 83 87 83 41 83 93 93 F1 90 A2"): "조안 2세",
    bytes.fromhex("83 7E 83 50 81 5B 83 8C 81 81 83 58 83 73 83 6D 83 89"): "미켈레 스피놀라",
    bytes.fromhex("83 45 83 8B 83 4F 81 81 83 78 83 4E"): "우르그 벡",
    bytes.fromhex("89 A4 8F 97"): "왕녀",
    bytes.fromhex("83 57 83 87 83 41 83 93 81 81 83 6F 83 8D 83 58"): "조안 바로스",
    bytes.fromhex("8F 68 89 AE"): "여관",
    bytes.fromhex("83 6B 83 57 83 93 83 4B 81 81 83 6B 83 4E 83 45"): "누진가 누쿠우",
    bytes.fromhex("95 BA 8E 6D"): "병사",
    bytes.fromhex("8E E5 90 6C 8C F6"): "주인공",
    bytes.fromhex("91 A2 91 44 8F 8A"): "조선소",
    bytes.fromhex("83 7D 83 80 83 8B 81 5B 83 4E"): "맘루크",
    bytes.fromhex("83 43 83 46 83 6A 83 60 83 46 83 8A"): "예니체리",
    # DISEV 발견 이벤트에서 확인한 추가 화자 태그.
    bytes.fromhex("8A C4 8E 40 8A AF"): "검사관",
    bytes.fromhex("83 43 83 93 83 66 83 42 83 49 82 CC 8E F1 97 CC"): "인디오의 족장",
    bytes.fromhex("89 A4 95 E6 82 CC 94 D4 90 6C"): "왕묘의 파수꾼",
    bytes.fromhex("92 86 8D 91 82 CC 98 56 90 6C"): "중국의 노인",
    bytes.fromhex("93 90 91 AF 82 CC 93 AA"): "도적 두목",
    bytes.fromhex("83 57 83 83 83 8F 82 CC 98 56 90 6C"): "자와의 노인",
    bytes.fromhex("83 43 83 93 83 68 82 CC 98 56 90 6C"): "인도의 노인",
    bytes.fromhex("91 6D 97 B5"): "승려",
    bytes.fromhex("92 CB 8C B4 83 67 93 60"): "츠카하라 보쿠덴",
    bytes.fromhex("83 7E 83 50 83 89 83 93 83 57 83 46 83 8D"): "미켈란젤로",
    bytes.fromhex("90 B3 91 71 89 40 82 CC 94 D4 90 6C"): "쇼소인의 파수꾼",
    bytes.fromhex("96 EC 95 9A 82 B9 82 E8"): "노부세리",
    bytes.fromhex("83 7A 83 62 83 65 83 93 83 67 83 62 83 67 91 B0 92 B7"): "호텐토트 족장",
    bytes.fromhex("83 70 83 68 83 93 82 CC 91 B0 92 B7"): "파돈의 족장",
    bytes.fromhex("83 41 83 7B 83 8A 83 57 83 6A 82 CC 91 B0 92 B7"): "아보리지니의 족장",
    bytes.fromhex("83 6A 83 85 81 5B 83 4D 83 6A 83 41 82 CC 91 B0 92 B7"): "뉴기니아의 족장",
    bytes.fromhex("83 43 83 6B 83 43 83 62 83 67 82 CC 91 B0 92 B7"): "이누이트의 족장",
    bytes.fromhex("83 43 83 93 83 66 83 42 83 41 83 93 82 CC 8F 55 92 B7"): "인디언의 족장",
    bytes.fromhex("83 41 83 7D 83 5D 83 6C 83 58 82 CC 91 B0 92 B7"): "아마조네스의 족장",
    bytes.fromhex("93 EC 8B C9 90 6C"): "남극인",
    bytes.fromhex("83 75 83 89 83 68"): "블라드",
    bytes.fromhex("83 82 83 4E 83 65 83 58 83 7D 93 F1 90 A2"): "목테수마 2세",
    bytes.fromhex("83 41 83 5E 83 8F 83 8B 83 70"): "아타왈파",
    bytes.fromhex("83 4C 83 58 83 4C 83 58"): "키스키스",
    bytes.fromhex("83 67 83 70 83 62 83 4E"): "토팍",
    bytes.fromhex("83 8C 83 49 83 69 83 8B 83 68"): "레오나르도",
    bytes.fromhex("83 6A 83 52 83 89 83 45 83 58"): "니콜라우스",
    bytes.fromhex("83 77 83 8D 83 6A 83 82"): "헤로니모",
    bytes.fromhex("83 41 83 58 83 65 83 4A 82 CC 96 F0 90 6C"): "아스테카 관리",
    bytes.fromhex("83 81 83 8A 83 5F 82 CC 90 65 95 83"): "메리다의 아버지",
    bytes.fromhex("83 68 81 5B 83 6A 83 83"): "도냐",
    bytes.fromhex("83 67 83 44 83 89 83 58 83 4A 83 89 82 CC 90 C2 94 4E"): "툴라스칼라의 청년",
    bytes.fromhex("83 67 83 44 83 89 83 58 83 4A 83 89 82 CC 90 ED 8E 6D"): "툴라스칼라의 전사",
    bytes.fromhex("83 5F 83 93 83 66 83 42"): "단디",
    bytes.fromhex("83 41 83 8B 83 78 81 5B 83 8B"): "알베르",
    bytes.fromhex("83 57 83 46 83 89 83 8B 83 68"): "제라르드",
    bytes.fromhex("83 79 83 67 83 8D 83 58"): "페트로스",
    bytes.fromhex("83 7D 83 8B 83 4E 83 58"): "마르쿠스",
    bytes.fromhex("83 57 83 85 83 8A 83 49"): "줄리오",
    bytes.fromhex("83 55 83 4B 81 5B"): "자가르",
    bytes.fromhex("83 5A 83 8A 83 6B"): "세리누",
}


@dataclass(frozen=True)
class ArchiveEntry:
    compressed: int
    uncompressed: int
    payload_offset: int


@dataclass(frozen=True)
class DiscoveryRow:
    index: int
    file_offset: int
    name: str
    category: int
    game_id: int
    still: int
    avi: int
    cg: int


@dataclass(frozen=True)
class Form:
    signature: bytes
    length: int
    kind: str
    jump_offset: int = -1


# Confirmed forms from the event viewer in cds95-mod plus patterns checked in
# the present DISEV.CDS.  Longer/more-specific signatures must precede shorter
# forms when they share a prefix.
FORMS = (
    # 00은 본문 하위 명령 그룹이다. 00 02 [u16]는 EXE의 AVI 재생 핸들러로
    # 들어간다. 이를 먼저 잡지 않으면 뒤의 02 0A 00을 빈 대사로 오인한다.
    Form(b"\x00\x02", 4, "AVI 재생"),
    Form(b"\x00\x1F", 4, "EVSTILL 이미지 표시"),
    Form(b"\x43\x2C\x08", 15, "교역품 조건 분기", 13),
    Form(b"\x43\x2D\x1C", 12, "능력치 비교 분기", 10),
    Form(b"\x43\x2E\x1C", 12, "능력치 비교2 분기", 10),
    Form(b"\x43\x2B\x1C", 12, "능력치 비교3 분기", 10),
    Form(b"\x43\x2C\x1C", 12, "소지금 비교 분기", 10),
    Form(b"\x43\x12\x05", 7, "아이템 조건 분기", 5),
    Form(b"\x43\x3A\x0B", 7, "발견물 조건 분기", 5),
    Form(b"\x43\x0F\x0E", 7, "미확인 0F0E 분기", 5),
    Form(b"\x43\x00\x15", 6, "미확인 0015 분기", 4),
    Form(b"\x43\x11", 6, "선택지 분기", 4),
    # 43 45는 퀘스트 스크립트 도구에서도 표준 점프(JUMP)로 생성된다.
    # 43 47은 바로 앞 0B(예/아니오) 대화의 응답을 받는 분기다.
    # 43 4B의 판정 기준은 아직 EXE에서 확정하지 못했다.
    Form(b"\x43\x45", 4, "이동", 2),
    Form(b"\x43\x47", 4, "예/아니오 응답 분기", 2),
    Form(b"\x43\x4B", 4, "미확인 4B 분기", 2),
    # 6D는 런타임의 현재 시나리오 파일명과 `C:STORY0.CDS`를 비교한다.
    Form(b"\x43\x6D", 4, "STORY0.CDS 외 분기", 2),
    # 6E는 런타임의 현재 시나리오 파일명(0x62989C)과 `C:STORY1.CDS`를
    # 비교한다. 일치하지 않으면 뒤의 u16 상대 이동량만큼 건너뛴다.
    Form(b"\x43\x6E", 4, "STORY1.CDS 외 분기", 2),
    Form(b"\x17\x00", 4, "국가 조건"),
    Form(b"\x17\x08", 4, "도시 조건"),
    Form(b"\x17\x10", 4, "건물 조건"),
    Form(b"\x17\x19", 4, "문화권 조건"),
    Form(b"\x1B\x16", 4, "연도 조건"),
    Form(b"\x1B\x17", 6, "연월 조건"),
    Form(b"\x1C\x16", 4, "연도 상한 조건"),
    Form(b"\x36\x16", 7, "연도 범위 조건"),
    Form(b"\x1B\x0B", 4, "발견 완료 조건"),
    Form(b"\x5E\x0B", 4, "미발견 조건"),
    Form(b"\x2A\x1C", 9, "수치 비교 (이상)"),
    Form(b"\x2B\x1C", 9, "능력치 조건"),
    Form(b"\x2C\x1C", 9, "수치 비교 (미만)"),
    Form(b"\x2D\x1C", 9, "수치 비교 (이하)"),
    # Random(분모) < 성공값. 현재 DISEV에는 성공값이 모두 1인 1/N 확률 조건만 있다.
    Form(b"\x2E\x1A", 11, "무작위 확률 조건"),
    Form(b"\x37\x0D", 4, "인물 런타임 조건"),
    Form(b"\x37\x12", 4, "후원자 런타임 조건"),
    # 상태값 수식은 `1A`(상수 u32, 9바이트) 또는 `20`(무작위 폭 u32 +
    # 시작값 u32, 13바이트)로 끝난다. parse_commands가 뒤의 수식 종류에
    # 맞춰 9/13바이트를 결정한다.
    Form(b"\x19\x1C", 9, "능력치 증가"),
    Form(b"\x1A\x1C", 9, "능력치 감소"),
    Form(b"\x26\x1C", 9, "능력치/기한 설정"),
    Form(b"\x22\x1C", 9, "능력치 설정"),
    Form(b"\x19\x14", 6, "금화 증가"),
    Form(b"\x1A\x14", 6, "금화 감소"),
    Form(b"\x12\x05", 4, "아이템 소지 조건"),
    Form(b"\x0F\x05", 4, "아이템 비소지 조건"),
    Form(b"\x0F\x0E", 4, "힌트 상태 활성 조건"),
    Form(b"\x12\x0E", 4, "힌트 상태 미활성 조건"),
    Form(b"\x00\x05", 4, "아이템 획득"),
    Form(b"\x57\x05", 4, "아이템 상실"),
    # 전역 이벤트 플래그 배열의 해당 항목을 아직 0일 때 1로 설정한다.
    Form(b"\x01\x15", 4, "이벤트 플래그 설정"),
    Form(b"\x26\x08", 4, "신도시 생성"),
    Form(b"\x26\x10", 7, "특수 건물 생성"),
    Form(b"\x06\x4D", 2, "다음 단계"),
    Form(b"\x04\x4D", 2, "이벤트 완전 종료"),
    Form(b"\x06\xFF", 1, "다음 단계"),
    Form(b"\x0E\x03", 4, "음원 재생"),
    Form(b"\x5A", 1, "후원자 계약 없음 조건"),
    Form(b"\x50", 1, "OR 연결(추정)"),
    Form(b"\x4C", 1, "이벤트 결과 코드 0"),
    Form(b"\x4D", 1, "이벤트 결과 코드 1"),
    Form(b"\x4E", 1, "이벤트 결과 코드 2"),
)


def read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_archive(data: bytes) -> list[ArchiveEntry]:
    if data[:4] not in (b"Ls12", b"LS11"):
        raise ValueError("DISEV.CDS가 LS12/LS11 아카이브가 아닙니다.")
    entries: list[ArchiveEntry] = []
    offset = 0x110
    while offset + 12 <= len(data):
        compressed, uncompressed, payload = struct.unpack_from(">III", data, offset)
        if compressed == 0:
            break
        if payload < 0x110 or payload + compressed > len(data):
            raise ValueError(f"파트 {len(entries)}의 압축 데이터 범위가 손상되었습니다.")
        entries.append(ArchiveEntry(compressed, uncompressed, payload))
        offset += 12
    if not entries:
        raise ValueError("DISEV.CDS에서 파트 테이블을 찾지 못했습니다.")
    return entries


def decode_part(archive: bytes, entry: ArchiveEntry, dictionary: bytes) -> bytes:
    source = archive[entry.payload_offset : entry.payload_offset + entry.compressed]
    if entry.compressed == entry.uncompressed:
        return source

    total_bits = entry.compressed * 8
    bit_position = 0
    output = bytearray(entry.uncompressed)
    output_position = 0
    distance = 0
    while output_position < entry.uncompressed and bit_position < total_bits:
        mask_length = 0
        while True:
            bit = (source[bit_position >> 3] >> (7 - (bit_position & 7))) & 1
            bit_position += 1
            mask_length += 1
            if bit == 0 or bit_position >= total_bits or mask_length >= 31:
                break
        if mask_length >= 31:
            break
        factor = 0
        for _ in range(mask_length):
            if bit_position >= total_bits:
                break
            factor = (factor << 1) | (
                (source[bit_position >> 3] >> (7 - (bit_position & 7))) & 1
            )
            bit_position += 1
        code = ((1 << mask_length) - 2) + factor
        if distance:
            for _ in range(3 + code):
                if output_position >= entry.uncompressed:
                    break
                output[output_position] = (
                    output[output_position - distance]
                    if output_position >= distance
                    else 0
                )
                output_position += 1
            distance = 0
        elif code < 256:
            output[output_position] = dictionary[code]
            output_position += 1
        else:
            distance = code - 256
    if output_position != entry.uncompressed:
        raise ValueError(
            f"LS12 압축 해제 실패: {output_position}/{entry.uncompressed}바이트"
        )
    return bytes(output)


def load_discovery_rows(exe_path: Path) -> list[DiscoveryRow]:
    exe = exe_path.read_bytes()
    target, image_base, sections = locate_discovery_record(exe, "카바신전", 672)
    offsets = discovery_table(exe, target, image_base, sections)
    rows: list[DiscoveryRow] = []
    for index, offset in enumerate(offsets):
        name_offset = va_to_file_offset(u32(exe, offset), image_base, sections)
        if name_offset is None:
            name = "<이름 포인터 오류>"
        else:
            end = exe.find(b"\0", name_offset, min(name_offset + 128, len(exe)))
            if end < 0:
                end = min(name_offset + 128, len(exe))
            name = exe[name_offset:end].decode("cp949", errors="replace")
        rows.append(
            DiscoveryRow(
                index=index,
                file_offset=offset,
                name=name,
                category=u32(exe, offset + 4),
                game_id=u32(exe, offset + 8),
                still=u32(exe, offset + STILL_OFFSET),
                avi=u32(exe, offset + AVI_OFFSET),
                cg=u32(exe, offset + CG_OFFSET),
            )
        )
    return rows

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def media_text(value: int) -> str:
    return "없음" if value == NO_MEDIA else str(value)


def safe_text(data: bytes) -> str:
    text = data.decode("cp949", errors="replace")
    result: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\r":
            result.append("<CR>")
        elif char == "\n":
            result.append("<LF>")
        elif char == "\t":
            result.append("<TAB>")
        elif code < 0x20 or code == 0x7F:
            result.append(f"<{code:02X}>")
        else:
            result.append(char)
    return "".join(result)


def normalize_dialogue_display(text: str) -> str:
    """Convert DISEV's full-width dialogue typography to ordinary UI text."""
    punctuation = str.maketrans({
        "\u3000": " ", "\u3002": ".", "\u3001": ",", "\u30fb": "·",
        "\u300c": '"', "\u300d": '"', "\u300e": '"', "\u300f": '"',
        "\u3010": "[", "\u3011": "]", "\u3014": "(", "\u3015": ")",
    })
    normalized: list[str] = []
    for char in text.translate(punctuation):
        code = ord(char)
        normalized.append(chr(code - 0xFEE0) if 0xFF01 <= code <= 0xFF5E else char)
    return "".join(normalized)


def decode_dialogue(data: bytes) -> tuple[str | None, str]:
    """Split the CP932 speaker tag and decode the Korean CP949 body."""
    speaker: str | None = None
    body_start = 0
    marker = data.find(b"\x81\x46", 0, min(len(data), 40))
    if marker >= 0:
        tag = data[:marker]
        speaker = SPEAKER_NAMES.get(tag)
        if speaker is None:
            speaker = tag.decode("cp932", errors="replace")
        body_start = marker + 2

    source = data[body_start:]
    cooked = bytearray()
    i = 0
    while i < len(source):
        if source.startswith(b"\x81\x5E", i):
            cooked.append(ord("/"))
            i += 2
            continue
        if i + 4 <= len(source) and source[i : i + 3] == b"\x81\x93\x82":
            # ％ｓ is replaced by the player name at runtime. 이름 지정
            # 이벤트의 ％Ｗ/％Ｘ/％Ｍ은 각각 "협", "오스트레일리아",
            # "남방대륙"으로 전개된다. 나머지 자리표만 명시 토큰으로 남긴다.
            if source[i + 3] == 0x93:
                cooked.extend("제독".encode("cp949"))
            elif source[i + 3] == 0x76:
                cooked.extend("협".encode("cp949"))
            elif source[i + 3] == 0x77:
                cooked.extend("오스트레일리아".encode("cp949"))
            elif source[i + 3] == 0x6C:
                cooked.extend("남방대륙".encode("cp949"))
            else:
                cooked.extend(f"<자리표 0x{source[i + 3]:02X}>".encode("cp949"))
            i += 4
            continue
        cooked.append(source[i])
        i += 1
    # UI에서는 전각 공백·문장부호·ASCII를 일반형으로 통일한다.
    return speaker, normalize_dialogue_display(safe_text(bytes(cooked))).rstrip(" ")


def hex_bytes(data: bytes) -> str:
    return " ".join(f"{value:02X}" for value in data)


def hexdump(data: bytes) -> list[str]:
    lines: list[str] = []
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        hex_part = " ".join(f"{value:02X}" for value in block)
        ascii_part = "".join(chr(value) if 0x20 <= value < 0x7F else "." for value in block)
        lines.append(f"  {offset:04X}  {hex_part:<47}  |{ascii_part}|")
    return lines


def chunk_end(data: bytes, starts: list[int], start: int) -> int:
    return min((value for value in starts if value > start), default=len(data))


def code_end(data: bytes, start: int, end: int) -> int:
    last = data.rfind(b"\xFF", start, end)
    return last + 1 if last >= start else end


def form_at(data: bytes, offset: int, end: int) -> Form | None:
    for form in FORMS:
        if offset + form.length <= end and data.startswith(form.signature, offset):
            return form
    return None


def likely_command_start(data: bytes, offset: int, end: int) -> bool:
    if offset >= end:
        return False
    if data[offset] in (0xFF, 0x0A, 0x01, 0x02, 0x0C):
        return True
    if offset + 1 < end and data[offset + 1] == 0x0A:
        return True
    return form_at(data, offset, end) is not None


def describe_form(form: Form, raw: bytes, absolute_offset: int) -> str:
    kind = form.kind
    if kind == "AVI 재생":
        return f"AVI 재생: 슬롯 {read_u16(raw, 2)}"
    if kind == "EVSTILL 이미지 표시":
        return f"EVSTILL 이미지 표시: 슬롯 {read_u16(raw, 2)}"
    if kind == "음원 재생":
        return f"음원 재생: 슬롯 {read_u16(raw, 2)}"
    if kind.endswith("조건") and len(raw) == 4 and raw[:1] == b"\x17":
        return f"{kind}: 값 {read_u16(raw, 2)}"
    if kind == "연도 조건":
        return f"연도 >= {read_u16(raw, 2)}"
    if kind == "연월 조건":
        return f"연월 조건: {read_u16(raw, 4)}년 {raw[2]}월"
    if kind == "연도 상한 조건":
        return f"연도 <= {read_u16(raw, 2)}"
    if kind == "연도 범위 조건":
        return f"연도 범위: {read_u16(raw, 2)}~{read_u16(raw, 5)}"
    if kind == "무작위 확률 조건":
        denominator = read_u32(raw, 2)
        success_count = read_u32(raw, 7)
        if raw[6] != 0x1A:
            return "무작위 확률 조건: 피연산자 형식 미확인"
        return f"무작위 확률 조건: {success_count} / {denominator}"
    if kind in ("인물 런타임 조건", "후원자 런타임 조건"):
        return f"{kind}: 번호 {read_u16(raw, 2)}"
    if kind in ("발견 완료 조건", "미발견 조건"):
        return f"{kind}: 발견물 ID {read_u16(raw, 2)}"
    if kind in ("능력치 조건", "수치 비교 (이상)", "수치 비교 (이하)", "수치 비교 (미만)"):
        stat = read_u16(raw, 2)
        value = read_u32(raw, 5)
        operator = {
            "능력치 조건": ">",
            "수치 비교 (이상)": ">=",
            "수치 비교 (이하)": "<=",
            "수치 비교 (미만)": "<",
        }[kind]
        return f"조건: {STAT_NAMES.get(stat, f'필드 {stat}')} {operator} {value}"
    if kind in ("능력치 증가", "능력치 감소", "능력치/기한 설정", "능력치 설정"):
        stat = read_u16(raw, 2)
        if raw[4] == 0x20 and len(raw) >= 13:
            width = read_u32(raw, 5)
            start = read_u32(raw, 9)
            end = start + max(width - 1, 0)
            value = f"무작위 {start}~{end}"
        else:
            value = read_u32(raw, 5)
        symbol = "+" if kind == "능력치 증가" else "-" if kind == "능력치 감소" else "="
        return f"{STAT_NAMES.get(stat, f'능력치 {stat}')} {symbol} {value}"
    if kind in ("금화 증가", "금화 감소"):
        symbol = "+" if kind == "금화 증가" else "-"
        return f"금화 {symbol}{read_u32(raw, 2)}"
    if kind in ("아이템 소지 조건", "아이템 비소지 조건", "아이템 획득", "아이템 상실"):
        return f"{kind}: 아이템 ID {read_u16(raw, 2)}"
    if kind in ("힌트 상태 활성 조건", "힌트 상태 미활성 조건"):
        return f"{kind}: 힌트 상태 ID {read_u16(raw, 2)}"
    if kind == "신도시 생성":
        return f"신도시 생성: 도시 ID {read_u16(raw, 2)}"
    if kind == "특수 건물 생성":
        return f"특수 건물 생성: 건물 {read_u16(raw, 2)}, 도시 {read_u16(raw, 5)}"
    if form.jump_offset >= 0 and form.jump_offset + 2 <= len(raw):
        relative = read_u16(raw, form.jump_offset)
        target = absolute_offset + form.length + relative
        extra = ""
        if kind == "아이템 조건 분기":
            extra = f", 아이템 ID {read_u16(raw, 3)}"
        elif kind == "교역품 조건 분기":
            extra = (
                f", 원산 도시 {read_u16(raw, 3)}, 교역품 {read_u16(raw, 6)}, "
                f"수량 {read_u32(raw, 9)}"
            )
        return f"{kind}{extra}, 상대 +0x{relative:X} -> 파트 +0x{target:X}"
    return kind


def parse_commands(
    data: bytes,
    start: int,
    end: int,
    row: DiscoveryRow | None,
    command_counts: Counter[str],
    unknown_counts: Counter[str],
    show_end: bool = True,
    include_hex: bool = True,
    include_offsets: bool = True,
) -> list[str]:
    lines: list[str] = []
    i = start
    while i < end:
        if data[i] == 0xFF:
            if show_end:
                offset_prefix = f"    +0x{i:04X}  " if include_offsets else "    "
                prefix = f"{offset_prefix}FF                         " if include_hex else offset_prefix
                lines.append(f"{prefix}덩이/갈래 끝")
                command_counts["덩이/갈래 끝"] += 1
            i += 1
            continue

        # Dialogue is either 0A text 00, or <window flag> 0A text 00.
        form = None if data[i] == 0x0A else form_at(data, i, end)
        if data[i] == 0x0A or (not form and i + 1 < end and data[i + 1] == 0x0A):
            flag = None if data[i] == 0x0A else data[i]
            text_start = i + 1 if flag is None else i + 2
            terminator = data.find(b"\0", text_start, end)
            if terminator < 0:
                terminator = end
                next_i = end
            else:
                next_i = terminator + 1
            raw = data[i:next_i]
            speaker, dialogue = decode_dialogue(data[text_start:terminator])
            speaker_text = f", 화자 {speaker}" if speaker else ""
            offset_prefix = f"    +0x{i:04X}  " if include_offsets else "    "
            prefix = f"{offset_prefix}{hex_bytes(raw[:18]):<53} " if include_hex else offset_prefix
            # 00 0A는 일반 대사 하위 명령이다. 0x00을 창 플래그로 노출하지 않는다.
            if flag in (None, 0):
                label = f"대사{speaker_text}: \"{dialogue}\""
            else:
                label = f"대사(창 플래그 {flag}{speaker_text}): \"{dialogue}\""
            lines.append(f"{prefix}{label}")
            if include_hex and len(raw) > 18:
                lines.append(f"             ... 대사 명령 전체 {len(raw)}바이트")
            command_counts["대사"] += 1
            i = next_i
            continue

        # 01/02/0C <u16> are DISEV media calls.  01 0B <u16> is also the
        # discovery-register command, so slot 11 is resolved using the linked
        # EXE row when possible and otherwise left explicitly ambiguous.
        if i + 3 <= end and data[i] in (0x01, 0x02, 0x0C):
            opcode = data[i]
            value = read_u16(data, i + 1)
            if opcode == 0x01 and data[i + 1] == 0x0B:
                if row is not None and row.still == 11 and value == 11:
                    label = "DSTILL 정지 이미지 재생: 슬롯 11 (EXE 매핑으로 판별)"
                    length = 3
                elif i + 4 <= end:
                    discovery_id = read_u16(data, i + 2)
                    label = f"발견물 등록/발견 처리: ID {discovery_id}"
                    length = 4
                else:
                    label = "01 0B: 정지 이미지 11/발견 처리 경계 불명"
                    length = 3
            else:
                media_name = {0x01: "DSTILL 이미지", 0x02: "AVI", 0x0C: "CG 애니메이션"}[opcode]
                label = f"{media_name} 재생: 슬롯 {value}"
                length = 3
            raw = data[i : i + length]
            offset_prefix = f"    +0x{i:04X}  " if include_offsets else "    "
            prefix = f"{offset_prefix}{hex_bytes(raw):<53} " if include_hex else offset_prefix
            lines.append(f"{prefix}{label}")
            command_counts[label.split(":", 1)[0]] += 1
            i += length
            continue

        form = form_at(data, i, end)
        if form is not None:
            length = form.length
            if (
                form.kind in ("능력치 증가", "능력치 감소", "능력치/기한 설정", "능력치 설정")
                and i + 13 <= end
                and data[i + 4] == 0x20
            ):
                length = 13
            raw = data[i : i + length]
            description = describe_form(form, raw, i)
            offset_prefix = f"    +0x{i:04X}  " if include_offsets else "    "
            prefix = f"{offset_prefix}{hex_bytes(raw):<53} " if include_hex else offset_prefix
            lines.append(f"{prefix}{description}")
            command_counts[form.kind] += 1
            i += length
            continue

        # Group unknown bytes until a known command boundary (maximum 16
        # bytes), preserving the exact sequence in the annotation and again in
        # the complete hexdump below.
        j = i + 1
        while j < end and j - i < 16 and not likely_command_start(data, j, end):
            j += 1
        raw = data[i:j]
        key = hex_bytes(raw)
        offset_prefix = f"    +0x{i:04X}  " if include_offsets else "    "
        prefix = f"{offset_prefix}{key:<53} " if include_hex else offset_prefix
        suffix = "미확인 명령/데이터" if include_hex else "미확인 명령/데이터 (파트 전체 HEX 탭 참고)"
        lines.append(f"{prefix}{suffix}")
        unknown_counts[key] += 1
        command_counts["미확인 명령/데이터"] += 1
        i = j
    return lines


def validate_part(data: bytes, part_index: int) -> tuple[int, list[tuple[int, int]]]:
    if len(data) < 8:
        raise ValueError(f"파트 {part_index}: 헤더가 너무 짧습니다.")
    step = read_u16(data, 0)
    slot_count = read_u16(data, 2)
    if not 1 <= slot_count <= 16 or 4 + slot_count * 4 > len(data):
        raise ValueError(f"파트 {part_index}: 슬롯 수/오프셋 표가 올바르지 않습니다.")
    slots: list[tuple[int, int]] = []
    for slot in range(slot_count):
        condition = 4 + read_u16(data, 4 + slot * 4)
        body = 4 + read_u16(data, 6 + slot * 4)
        if not (4 + slot_count * 4 <= condition < len(data)):
            raise ValueError(f"파트 {part_index} 슬롯 {slot}: 조건 오프셋 오류")
        if not (4 + slot_count * 4 <= body < len(data)):
            raise ValueError(f"파트 {part_index} 슬롯 {slot}: 본문 오프셋 오류")
        slots.append((condition, body))
    return step, slots


def build_dump(disev_path: Path, exe_path: Path) -> str:
    archive = disev_path.read_bytes()
    exe = exe_path.read_bytes()
    entries = parse_archive(archive)
    dictionary = archive[0x10:0x110]
    decoded = [decode_part(archive, entry, dictionary) for entry in entries]
    rows = load_discovery_rows(exe_path)

    if len(rows) != len(decoded):
        raise ValueError(
            f"발견물 테이블({len(rows)})과 DISEV 파트({len(decoded)}) 수가 다릅니다. "
            "안전하게 1:1 매핑할 수 없습니다."
        )

    parsed = [validate_part(part, index) for index, part in enumerate(decoded)]
    slot_counts = Counter(len(slots) for _step, slots in parsed)
    steps = Counter(step for step, _slots in parsed)
    command_counts: Counter[str] = Counter()
    unknown_counts: Counter[str] = Counter()
    total_decoded = sum(len(part) for part in decoded)

    out: list[str] = []
    add = out.append
    add("DISEV.CDS 이벤트 스크립트 전체 분석")
    add("=" * 78)
    add(f"생성 시각: {datetime.now().astimezone().isoformat(timespec='seconds')}")
    add(f"입력 DISEV: {disev_path}")
    add(f"DISEV 크기: {len(archive):,}바이트")
    add(f"DISEV SHA-256: {sha256(archive)}")
    add(f"매핑 EXE: {exe_path}")
    add(f"EXE SHA-256: {sha256(exe)}")
    add("")
    add("[중요]")
    add("- '확정' 표시는 현재 파일 및 실행 흐름과 교차 검증된 구조/명령입니다.")
    add("- '추정' 또는 '미확인'은 의미를 임의로 확정하지 않은 값입니다.")
    add("- 모든 파트 끝에 압축 해제된 원문 HEX를 싣기 때문에 미확인 명령도 누락되지 않습니다.")
    add("- 발견물 이름/ID/매체는 CDS_95.EXE의 연속 0x5C바이트 테이블을 1:1로 연결한 참고 정보입니다.")
    add("")
    add("1. LS12 아카이브 구조")
    add("- 0x000: 16바이트 식별 헤더 ('Ls12' 또는 'LS11', 나머지 패딩)")
    add("- 0x010: 256바이트 LS12 사전")
    add("- 0x110: 파트 테이블; 항목당 12바이트, 모두 빅엔디언 u32")
    add("         [압축 크기, 압축 해제 크기, 압축 payload 파일 오프셋]")
    add("- 파트 테이블 끝: 12바이트 항목의 압축 크기 0으로 판별")
    add(f"- 파트 수: {len(entries)}개")
    add(f"- 압축 해제 스크립트 총량: {total_decoded:,}바이트")
    add(f"- 파트 크기: 최소 {min(map(len, decoded)):,}, 최대 {max(map(len, decoded)):,}바이트")
    add(f"- 슬롯 수 분포: {dict(sorted(slot_counts.items()))}")
    add(f"- 내부 단계 번호 고유값: {len(steps)}개")
    add("")
    add("LS12 식별 헤더 HEX:")
    add("  " + hex_bytes(archive[:0x10]))
    add("LS12 사전(256바이트) HEX:")
    out.extend(hexdump(dictionary))
    add("")
    add("2. 압축 해제된 파트 공통 구조")
    add("- +0x00: 내부 단계 번호 (u16 little-endian)")
    add("- +0x02: 슬롯 수 (u16 little-endian)")
    add("- +0x04: 슬롯별 4바이트 오프셋 표")
    add("         [조건 상대 오프셋 u16, 본문 상대 오프셋 u16]")
    add("- 실제 덩이 위치 = +0x04 + 상대 오프셋")
    add("- 각 조건/본문 덩이는 FF로 갈래 또는 명령열을 끝냅니다.")
    add("- 대사: [창 플래그] 0A [CP949 문자열] 00")
    add("")
    add("3. 확인된 주요 명령")
    add("- 01 [u16]: DSTILL 이미지 재생")
    add("- 02 [u16]: AVI 재생")
    add("- 0C [u16]: CG 애니메이션 재생")
    add("- 01 0B [발견물 ID u16]: 발견물 등록/발견 처리")
    add("- 0A [CP949] 00: 대사")
    add("- 4C FF: 이벤트 종료")
    add("- 4E FF: 이벤트 미종료/반복")
    add("- 그 밖의 조건·분기·아이템·금화 명령은 각 파트 주석 참조")
    add("")
    add("4. 전체 파트")

    for index, (entry, part, row, parsed_part) in enumerate(zip(entries, decoded, rows, parsed)):
        step, slots = parsed_part
        category = CATEGORY_NAMES.get(row.category, f"미확인({row.category})")
        compressed_blob = archive[
            entry.payload_offset : entry.payload_offset + entry.compressed
        ]
        add("")
        add("=" * 78)
        add(
            f"PART {index:03d} / 발견물 순번 {index + 1} / {row.name} "
            f"(게임 ID {row.game_id}, {category})"
        )
        add("-" * 78)
        add(
            f"아카이브: payload 0x{entry.payload_offset:08X}, "
            f"압축 {entry.compressed:,}바이트, 해제 {entry.uncompressed:,}바이트, "
            f"압축 SHA-256 {sha256(compressed_blob)}"
        )
        add(
            f"EXE 매핑: 레코드 파일 오프셋 0x{row.file_offset:08X}, "
            f"정지영상 {media_text(row.still)}, AVI {media_text(row.avi)}, CG {media_text(row.cg)}"
        )
        add(f"파트 헤더: 내부 단계 번호 {step}, 슬롯 수 {len(slots)}")
        starts = sorted({value for pair in slots for value in pair})
        for slot_index, (condition, body) in enumerate(slots):
            add(
                f"  슬롯 {slot_index}: 조건 +0x{condition:04X} "
                f"(상대 0x{condition - 4:04X}), 본문 +0x{body:04X} "
                f"(상대 0x{body - 4:04X})"
            )
        for slot_index, (condition, body) in enumerate(slots):
            for label, start in (("조건", condition), ("본문", body)):
                end = chunk_end(part, starts, start)
                semantic_end = code_end(part, start, end)
                add(
                    f"  [{label} 슬롯 {slot_index}] +0x{start:04X}~+0x{end - 1:04X} "
                    f"({end - start}바이트)"
                )
                out.extend(
                    parse_commands(
                        part,
                        start,
                        semantic_end,
                        row,
                        command_counts,
                        unknown_counts,
                    )
                )
                if semantic_end < end:
                    padding = part[semantic_end:end]
                    add(
                        f"    +0x{semantic_end:04X}  {hex_bytes(padding[:24]):<53} "
                        f"명령열 뒤 여백/보존 데이터 ({len(padding)}바이트)"
                    )
                    if len(padding) > 24:
                        add("             ... 전체 값은 아래 원문 HEX 참조")
        add("  [압축 해제 원문 HEX - 파트 전체]")
        out.extend(hexdump(part))

    add("")
    add("=" * 78)
    add("5. 명령 출현 집계")
    add("=" * 78)
    for name, count in command_counts.most_common():
        add(f"{name}: {count:,}회")
    add("")
    add("6. 미확인 명령/데이터 패턴 상위 200개")
    add("=" * 78)
    add("미확인 바이트는 삭제되거나 무시된 것이 아니며 각 파트 원문 HEX에 전부 보존되어 있습니다.")
    for value, count in unknown_counts.most_common(200):
        add(f"{count:6,}회  {value}")

    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="DISEV.CDS 전체 이벤트 스크립트 분석 TXT 생성")
    parser.add_argument("disev", type=Path, help="DISEV.CDS 경로")
    parser.add_argument("--exe", type=Path, required=True, help="발견물 매핑용 CDS_95.EXE 경로")
    parser.add_argument("--output", type=Path, required=True, help="출력 TXT 경로")
    args = parser.parse_args()

    text = build_dump(args.disev.resolve(), args.exe.resolve())
    args.output.resolve().write_text(text, encoding="utf-8-sig", newline="\r\n")
    print(f"완료: {args.output.resolve()}")
    print(f"TXT 크기: {args.output.resolve().stat().st_size:,}바이트")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        raise SystemExit(f"오류: {exc}")
