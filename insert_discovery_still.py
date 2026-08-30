#!/usr/bin/env python3
r"""Insert a 320x240 still image into DSTILL.CDS and link a discovery record.

The discovery record is located from its Korean name and game ID, rather than
from a fixed EXE file offset.  It therefore also works with EXEs whose section
layout has changed, as long as the original 92-byte discovery-record format is
still used.

Requires Pillow::

    python -m pip install pillow

Example (Kaaba Temple)::

    python tools\insert_discovery_still.py ^
      --exe D:\\Games\\CDS_95.EXE ^
      --dstill D:\\Games\\DSTILL.CDS ^
      --image E:\\Download\\DSTILL\\kaaba_pencil_1500s_clean_320x240_8bit.bmp

The script creates timestamped ``.before_...bak`` files before modifying
either game file.  By default it replaces an unreferenced slot.  ``--append``
adds a new three-part image at the end of DSTILL instead, preserving every
existing image.
"""

from __future__ import annotations

import argparse
import shutil
import struct
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:
    from PIL import Image
except ImportError as exc:  # pragma: no cover - helpful command-line error
    raise SystemExit("Pillow가 필요합니다: python -m pip install pillow") from exc


RECORD_SIZE = 0x5C
NO_MEDIA = 0xFFFFFFFF
STILL_OFFSET = 0x0C
AVI_OFFSET = 0x10
CG_OFFSET = 0x14
NATIVE_PALETTE_SIZE = 86
NATIVE_PALETTE_START = 160


@dataclass(frozen=True)
class PeSection:
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True)
class InjectionPlan:
    target_offset: int
    table_rows: int
    image_count: int
    slot: int
    free_slots: list[int]
    append: bool = False


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_pe_sections(exe: bytes) -> tuple[int, list[PeSection]]:
    if exe[:2] != b"MZ":
        raise ValueError("PE 실행 파일이 아닙니다.")
    pe_offset = u32(exe, 0x3C)
    if exe[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("PE 헤더를 찾지 못했습니다.")
    section_count = struct.unpack_from("<H", exe, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", exe, pe_offset + 20)[0]
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", exe, optional)[0]
    if magic == 0x10B:
        image_base = u32(exe, optional + 28)
    elif magic == 0x20B:
        image_base = struct.unpack_from("<Q", exe, optional + 24)[0]
    else:
        raise ValueError("지원하지 않는 PE 선택 헤더입니다.")
    first_section = optional + optional_size
    sections = []
    for index in range(section_count):
        offset = first_section + index * 40
        virtual_size = u32(exe, offset + 8)
        rva = u32(exe, offset + 12)
        raw_size = u32(exe, offset + 16)
        raw_offset = u32(exe, offset + 20)
        sections.append(PeSection(rva, virtual_size, raw_offset, raw_size))
    return image_base, sections


def va_to_file_offset(va: int, image_base: int, sections: list[PeSection]) -> int | None:
    if va < image_base:
        return None
    rva = va - image_base
    for section in sections:
        section_size = max(section.virtual_size, section.raw_size)
        if section.rva <= rva < section.rva + section_size:
            offset = section.raw_offset + rva - section.rva
            if offset < section.raw_offset + section.raw_size:
                return offset
    return None


def record_has_name(exe: bytes, offset: int, image_base: int, sections: list[PeSection]) -> bool:
    if offset < 0 or offset + RECORD_SIZE > len(exe):
        return False
    category = u32(exe, offset + 4)
    game_id = u32(exe, offset + 8)
    name_offset = va_to_file_offset(u32(exe, offset), image_base, sections)
    if category > 7 or game_id > 10000 or name_offset is None:
        return False
    terminator = exe.find(b"\0", name_offset, min(name_offset + 96, len(exe)))
    return terminator > name_offset


def locate_discovery_record(exe: bytes, name: str, game_id: int) -> tuple[int, int, list[PeSection]]:
    image_base, sections = parse_pe_sections(exe)
    target_name = name.encode("cp949") + b"\0"
    game_id_bytes = struct.pack("<I", game_id)
    matches: list[int] = []
    cursor = 0
    while True:
        id_offset = exe.find(game_id_bytes, cursor)
        if id_offset < 0:
            break
        cursor = id_offset + 1
        record_offset = id_offset - 8
        if not record_has_name(exe, record_offset, image_base, sections):
            continue
        name_offset = va_to_file_offset(u32(exe, record_offset), image_base, sections)
        if name_offset is not None and exe.startswith(target_name, name_offset):
            matches.append(record_offset)
    if len(matches) != 1:
        raise ValueError(f"'{name}' (게임 ID {game_id}) 레코드를 하나로 특정하지 못했습니다: {matches}")
    return matches[0], image_base, sections


def discovery_table(exe: bytes, target_offset: int, image_base: int, sections: list[PeSection]) -> list[int]:
    """Expand the contiguous 0x5C-byte table surrounding the target record."""
    first = target_offset
    while record_has_name(exe, first - RECORD_SIZE, image_base, sections):
        first -= RECORD_SIZE
    rows: list[int] = []
    offset = first
    while record_has_name(exe, offset, image_base, sections):
        rows.append(offset)
        offset += RECORD_SIZE
    if target_offset not in rows or len(rows) < 100:
        raise ValueError("발견물 테이블 범위를 검증하지 못했습니다.")
    return rows


def parse_ls12(archive: bytes) -> list[tuple[int, int, int]]:
    if archive[:4] not in (b"Ls12", b"LS11"):
        raise ValueError("DSTILL.CDS가 LS12 아카이브가 아닙니다.")
    entries = []
    offset = 0x110
    while offset + 12 <= len(archive):
        compressed, uncompressed, payload_offset = struct.unpack_from(">III", archive, offset)
        if compressed == 0:
            break
        if payload_offset + compressed > len(archive):
            raise ValueError("DSTILL.CDS의 파트 범위가 손상되었습니다.")
        entries.append((compressed, uncompressed, payload_offset))
        offset += 12
    if not entries or len(entries) % 3:
        raise ValueError("DSTILL.CDS의 그림/팔레트/크기 파트 구성이 올바르지 않습니다.")
    return entries


def validate_source_bmp(image_path: Path) -> tuple[int, int]:
    """Require the same external BMP form used by the extracted DSTILL art."""
    raw = image_path.read_bytes()
    if raw[:2] != b"BM" or len(raw) < 54:
        raise ValueError("이미지는 BMP 파일이어야 합니다.")
    # BITMAPFILEHEADER is always 14 bytes; +0x0A is the pixel-data offset,
    # not the start of the DIB header.
    dib_offset = 14
    if dib_offset + 20 > len(raw) or u32(raw, dib_offset) < 40:
        raise ValueError("BMP 헤더가 손상되었습니다.")
    width = struct.unpack_from("<i", raw, dib_offset + 4)[0]
    height = abs(struct.unpack_from("<i", raw, dib_offset + 8)[0])
    bits_per_pixel = struct.unpack_from("<H", raw, dib_offset + 14)[0]
    compression = u32(raw, dib_offset + 16)
    if (width, height) != (320, 240):
        raise ValueError(f"이미지 크기는 320x240이어야 합니다: {width}x{height}")
    if bits_per_pixel != 8 or compression != 0:
        raise ValueError("이미지는 무압축 8비트 팔레트 BMP여야 합니다.")
    with Image.open(image_path) as image:
        if image.format != "BMP" or image.mode != "P":
            raise ValueError("이미지는 8비트 인덱스 팔레트 BMP여야 합니다.")
        palette = image.getpalette()
        if palette is None or len(palette) < 256 * 3:
            raise ValueError("이미지에 256색 BMP 팔레트가 없습니다.")
    return width, height


def encode_native_still(image_path: Path) -> tuple[bytes, bytes, bytes]:
    validate_source_bmp(image_path)
    with Image.open(image_path) as image:
        # A BMP extracted from DSTILL already uses the game's native indices
        # 160..245.  Preserve it byte-for-byte instead of quantizing it again.
        flattened = image.get_flattened_data() if hasattr(image, "get_flattened_data") else image.getdata()
        native_pixels = bytes(flattened)
        native_palette = image.getpalette()
        if (
            native_pixels
            and min(native_pixels) >= NATIVE_PALETTE_START
            and max(native_pixels) < NATIVE_PALETTE_START + NATIVE_PALETTE_SIZE
            and native_palette is not None
            and len(native_palette) >= 256 * 3
        ):
            brg_palette = bytearray()
            for index in range(
                NATIVE_PALETTE_START,
                NATIVE_PALETTE_START + NATIVE_PALETTE_SIZE,
            ):
                red, green, blue = native_palette[index * 3 : index * 3 + 3]
                brg_palette.extend((blue, red, green))
            return native_pixels, bytes(brg_palette), struct.pack("<II", 320, 240)

        quantized = image.convert("RGB").quantize(
            colors=NATIVE_PALETTE_SIZE,
            method=Image.Quantize.MEDIANCUT,
            dither=Image.Dither.NONE,
        )
    flattened = quantized.get_flattened_data() if hasattr(quantized, "get_flattened_data") else quantized.getdata()
    pixels = bytes(index + NATIVE_PALETTE_START for index in flattened)
    rgb_palette = quantized.getpalette()[: NATIVE_PALETTE_SIZE * 3]
    brg_palette = bytearray()
    for index in range(NATIVE_PALETTE_SIZE):
        red, green, blue = rgb_palette[index * 3 : index * 3 + 3]
        brg_palette.extend((blue, red, green))
    return pixels, bytes(brg_palette), struct.pack("<II", 320, 240)


def replace_slot(archive: bytes, entries: list[tuple[int, int, int]], slot: int, assets: tuple[bytes, bytes, bytes]) -> bytes:
    replacement = {slot * 3 + index: blob for index, blob in enumerate(assets)}
    blobs = [replacement.get(index, archive[offset : offset + compressed])
             for index, (compressed, _uncompressed, offset) in enumerate(entries)]
    table_end = 0x110 + len(entries) * 12 + 4
    output = bytearray(archive[:0x110])
    payload_offset = table_end
    for index, blob in enumerate(blobs):
        if index in replacement:
            compressed = uncompressed = len(blob)  # New data is intentionally uncompressed.
        else:
            compressed, uncompressed, _old_offset = entries[index]
        output.extend(struct.pack(">III", compressed, uncompressed, payload_offset))
        payload_offset += compressed
    output.extend(b"\0\0\0\0")
    output.extend(b"".join(blobs))
    return bytes(output)


def append_slot(
    archive: bytes,
    entries: list[tuple[int, int, int]],
    assets: tuple[bytes, bytes, bytes],
) -> bytes:
    """Append one image as pixel/palette/size parts without replacing assets."""
    blobs = [archive[offset : offset + compressed]
             for compressed, _uncompressed, offset in entries]
    metadata = [(compressed, uncompressed)
                for compressed, uncompressed, _offset in entries]
    blobs.extend(assets)
    metadata.extend((len(blob), len(blob)) for blob in assets)

    table_end = 0x110 + len(blobs) * 12 + 4
    output = bytearray(archive[:0x110])
    payload_offset = table_end
    for (compressed, uncompressed), blob in zip(metadata, blobs):
        output.extend(struct.pack(">III", compressed, uncompressed, payload_offset))
        payload_offset += compressed
    output.extend(b"\0\0\0\0")
    output.extend(b"".join(blobs))
    return bytes(output)


def backup(path: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = path.with_name(f"{path.name}.before_discovery_still_{stamp}.bak")
    shutil.copy2(path, backup_path)
    return backup_path


def atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".discovery_still.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def make_plan(exe_path: Path, dstill_path: Path, discovery_name: str, game_id: int, requested_slot: int | None = None) -> InjectionPlan:
    exe = exe_path.read_bytes()
    archive = dstill_path.read_bytes()
    target, image_base, sections = locate_discovery_record(exe, discovery_name, game_id)
    table_rows = discovery_table(exe, target, image_base, sections)
    entries = parse_ls12(archive)
    image_count = len(entries) // 3
    # The target's existing slot is reusable; other discovery references are not.
    used_slots = {u32(exe, row + STILL_OFFSET) for row in table_rows if row != target}
    used_slots = {slot for slot in used_slots if 0 <= slot < image_count}
    free_slots = sorted(set(range(image_count)) - used_slots)
    if requested_slot is None:
        if not free_slots:
            raise ValueError("미참조 DSTILL 슬롯이 없습니다.")
        slot = free_slots[0]
    else:
        slot = requested_slot
        if not 0 <= slot < image_count:
            raise ValueError(f"슬롯 범위는 0~{image_count - 1}입니다.")
        if slot in used_slots:
            raise ValueError(f"DSTILL 슬롯 {slot}은 다른 발견물이 사용 중입니다.")
    return InjectionPlan(target, len(table_rows), image_count, slot, free_slots)


def make_append_plan(
    exe_path: Path,
    dstill_path: Path,
    discovery_name: str,
    game_id: int,
) -> InjectionPlan:
    exe = exe_path.read_bytes()
    archive = dstill_path.read_bytes()
    target, image_base, sections = locate_discovery_record(exe, discovery_name, game_id)
    table_rows = discovery_table(exe, target, image_base, sections)
    entries = parse_ls12(archive)
    if len(entries) % 3:
        raise ValueError("DSTILL 파트 수가 그림/팔레트/크기 단위로 나누어지지 않습니다.")
    image_count = len(entries) // 3
    return InjectionPlan(target, len(table_rows), image_count, image_count, [], True)


def insert_still(
    exe_path: Path,
    dstill_path: Path,
    image_path: Path,
    discovery_name: str = "카바신전",
    game_id: int = 672,
    requested_slot: int | None = None,
    replace_other_media: bool = False,
    append: bool = False,
) -> tuple[InjectionPlan, Path, Path]:
    if append:
        if requested_slot is not None:
            raise ValueError("--append와 --slot은 함께 사용할 수 없습니다.")
        plan = make_append_plan(exe_path, dstill_path, discovery_name, game_id)
    else:
        plan = make_plan(exe_path, dstill_path, discovery_name, game_id, requested_slot)
    assets = encode_native_still(image_path)
    exe = exe_path.read_bytes()
    archive = dstill_path.read_bytes()
    entries = parse_ls12(archive)
    new_archive = (
        append_slot(archive, entries, assets)
        if plan.append
        else replace_slot(archive, entries, plan.slot, assets)
    )
    new_exe = bytearray(exe)
    struct.pack_into("<I", new_exe, plan.target_offset + STILL_OFFSET, plan.slot)
    if replace_other_media:
        struct.pack_into("<I", new_exe, plan.target_offset + AVI_OFFSET, NO_MEDIA)
        struct.pack_into("<I", new_exe, plan.target_offset + CG_OFFSET, NO_MEDIA)
    archive_backup = backup(dstill_path)
    exe_backup = backup(exe_path)
    atomic_write(dstill_path, new_archive)
    atomic_write(exe_path, bytes(new_exe))
    return plan, archive_backup, exe_backup


def main() -> int:
    parser = argparse.ArgumentParser(description="DSTILL 정지 이미지 삽입 및 발견물 EXE 레코드 연결")
    parser.add_argument("--exe", type=Path, required=True, help="CDS_95.EXE 경로")
    parser.add_argument("--dstill", type=Path, required=True, help="DSTILL.CDS 경로")
    parser.add_argument("--image", type=Path, required=True, help="삽입할 320x240 BMP/이미지 경로")
    parser.add_argument("--discovery-name", default="카바신전", help="EXE 안의 발견물 이름")
    parser.add_argument("--game-id", type=int, default=672, help="발견물 게임 ID (카바신전: 672)")
    parser.add_argument("--slot", type=int, help="사용할 DSTILL 슬롯 번호 (생략하면 미참조 슬롯 자동 선택)")
    parser.add_argument("--append", action="store_true", help="기존 그림을 보존하고 마지막에 새 슬롯 추가")
    parser.add_argument("--replace-other-media", action="store_true", help="AVI/CG 지정도 제거하고 정지 이미지를 강제")
    parser.add_argument("--dry-run", action="store_true", help="수정하지 않고 대상과 슬롯만 확인")
    args = parser.parse_args()

    validate_source_bmp(args.image)
    if args.append and args.slot is not None:
        parser.error("--append와 --slot은 함께 사용할 수 없습니다.")
    plan = (
        make_append_plan(args.exe, args.dstill, args.discovery_name, args.game_id)
        if args.append
        else make_plan(args.exe, args.dstill, args.discovery_name, args.game_id, args.slot)
    )

    print(f"발견물: {args.discovery_name} (게임 ID {args.game_id})")
    print(f"레코드 파일 오프셋: 0x{plan.target_offset:X}; 발견물 테이블: {plan.table_rows}개")
    print(f"DSTILL: {plan.image_count}개 슬롯, 선택 슬롯: {plan.slot}, 미참조 슬롯: {plan.free_slots}")
    if args.dry_run:
        return 0

    plan, archive_backup, exe_backup = insert_still(
        args.exe, args.dstill, args.image, args.discovery_name, args.game_id,
        args.slot, args.replace_other_media, args.append,
    )
    action = "추가" if plan.append else "삽입"
    print(f"완료: DSTILL 슬롯 {plan.slot}에 {action}하고 EXE 레코드에 연결했습니다.")
    print(f"백업: {archive_backup.name}, {exe_backup.name}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        raise SystemExit(f"오류: {exc}")
