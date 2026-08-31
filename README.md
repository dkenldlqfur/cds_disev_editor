# 대항해시대 3 DISEV 에디터

대항해시대 3 한국어판의 `DISEV.CDS` 발견물 이벤트 스크립트를 확인하고 편집하는 Windows용 도구입니다.

최신 버전: [![GitHub Release](https://img.shields.io/github/v/release/dkenldlqfur/cds_disev_editor?display_name=tag&label=%EC%B5%9C%EC%8B%A0%20%EB%B2%84%EC%A0%84)](https://github.com/dkenldlqfur/cds_disev_editor/releases/latest)

## 주요 기능

- `DISEV.CDS` 아카이브 열기·저장
- `CDS_95.EXE`의 발견물 목록과 이벤트 파트 매핑
- 조건과 본문 명령을 사람이 읽을 수 있는 형태로 표시·편집
- 조건/본문 길이 변경 시 파트 크기와 본문 시작 위치 자동 보정
- 삽입·제거 시 상대 행 이동 대상 자동 보정
- 조건, 명령, 발견물 목록의 검색·선택·되돌리기
- 명령 설명 탭 및 바이트코드 안내
- 테마 저장 및 다음 실행 시 복원
- GitHub Release 기반 자동 업데이트

## 사용 방법

1. `DISEV_Editor.exe`를 실행합니다.
2. **DISEV 열기**를 눌러 게임 폴더의 `DISEV.CDS`를 선택합니다.
3. 같은 폴더에 `CDS_95.EXE`가 있으면 발견물 이름과 파트가 자동으로 연결됩니다.
4. 왼쪽에서 발견물을 선택하고, 오른쪽에서 조건과 명령을 수정합니다.
5. **변경 적용**으로 현재 파트에 반영한 뒤 **저장**합니다.

저장하면 기존 `DISEV.CDS`와 같은 폴더에 시간표시 백업 파일이 생성됩니다.

## 주의 사항

- 편집 전에는 게임 파일을 별도로 백업해 두는 것을 권장합니다.
- 분석되지 않은 명령과 조건은 원본 바이트를 보존하도록 설계되어 있습니다. 의미가 확인되지 않은 영역을 임의로 바꾸지 마세요.
- 게임이 실행 중이면 수정한 `DISEV.CDS`는 반영되지 않을 수 있으므로 게임을 완전히 종료한 뒤 수정하고 다시 실행하세요.

## 자동 업데이트

시작 시 GitHub의 최신 정식 Release를 확인합니다. 새 버전이 있으면 상단에 **업데이트 확인** 버튼이 나타납니다.

업데이트는 다음 순서로 처리됩니다.

1. Release ZIP을 다운로드하고, 제공된 경우 SHA-256을 검증합니다.
2. ZIP에서 `DISEV_Editor.exe`를 추출합니다.
3. 편집기가 종료된 뒤 기존 EXE를 새 파일로 교체하고 재실행합니다.
4. 새 버전에서 업데이트 내역을 표시합니다.

자동 업데이트 설치는 배포 EXE에서만 동작하며, `.pyw` 직접 실행에서는 설치하지 않습니다.

## 개발 환경

- Python 3.14 이상
- Tkinter
- PyInstaller

소스 실행:

```powershell
py -3 DISEV_Editor.pyw
```

배포 빌드:

```powershell
py -3 -m PyInstaller --noconfirm --clean DISEV_Editor.spec
```

빌드 결과는 `dist/DISEV_Editor.exe`에 생성됩니다.

## Release 배포 규칙

자동 업데이트가 Release 파일을 찾으려면 아래 형식을 지켜야 합니다.

- 태그: `v0.2`처럼 버전 번호 사용
- ZIP 파일명: `DISEV_Editor_v0.2.zip`
- ZIP 내부: `DISEV_Editor.exe` 파일 하나
- Release 본문: 사용자에게 표시할 업데이트 내역

버전은 `Resources/data/app_config.json`의 `version`을 먼저 올린 뒤 빌드합니다.

## 프로젝트 구성

```text
DISEV_Editor.pyw              편집기 본체
Resources/dump_disev.py       DISEV 아카이브 분석·입출력
Resources/discovery_records.py 발견물 EXE 레코드 탐색·해석
Resources/data/app_config.json 버전 및 업데이트 설정
Resources/data/ui_texts.json  화면 문구
Resources/splash.jpg          배포 EXE 시작 스플래시
Resources/Icon.ico            프로그램 아이콘
DISEV_Editor.spec             PyInstaller 배포 정의
```
