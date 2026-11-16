#!/usr/bin/env python3
"""Fail if an APK's 64-bit native libraries would not load on a 16 KB-page device (#122).

Android 15+ devices with 16 KB pages load a `lib/<abi>/*.so` only when every ELF LOAD
segment is aligned to at least 16 KB, and Google Play requires it for apps targeting
SDK 35+. For a library stored uncompressed (AGP's default since 8.5.1), its data must
also start on a 16 KB boundary in the zip, as `zipalign -c -P 16` checks. Only the
64-bit ABIs (arm64-v8a, x86_64) run with 16 KB pages, so only they are checked.

Usage: check-16kb-alignment.py <apk>
"""

import struct
import sys
import zipfile

PAGE = 16 * 1024
ABIS = ("lib/arm64-v8a/", "lib/x86_64/")
PT_LOAD = 1


def load_alignments(elf: bytes) -> list[int]:
    """The p_align of every LOAD segment of a 64-bit ELF image."""
    if elf[:4] != b"\x7fELF" or elf[4] != 2:
        raise ValueError("not a 64-bit ELF file")
    order = "<" if elf[5] == 1 else ">"
    (phoff,) = struct.unpack_from(order + "Q", elf, 0x20)
    phentsize, phnum = struct.unpack_from(order + "HH", elf, 0x36)
    aligns = []
    for i in range(phnum):
        off = phoff + i * phentsize
        (ptype,) = struct.unpack_from(order + "I", elf, off)
        if ptype == PT_LOAD:
            aligns.append(struct.unpack_from(order + "Q", elf, off + 0x30)[0])
    return aligns


def data_offset(apk: zipfile.ZipFile, info: zipfile.ZipInfo) -> int:
    """Where an entry's data starts: after its local file header, name and extra field."""
    apk.fp.seek(info.header_offset)
    header = apk.fp.read(30)
    name_len, extra_len = struct.unpack("<HH", header[26:30])
    return info.header_offset + 30 + name_len + extra_len


def main(path: str) -> int:
    failures = 0
    checked = 0
    with zipfile.ZipFile(path) as apk:
        for info in apk.infolist():
            if not (info.filename.startswith(ABIS) and info.filename.endswith(".so")):
                continue
            checked += 1
            problems = []
            aligns = load_alignments(apk.read(info))
            if not aligns or min(aligns) < PAGE:
                problems.append(f"LOAD segment aligned to {min(aligns, default=0):#x}, want >= {PAGE:#x}")
            if info.compress_type == zipfile.ZIP_STORED and data_offset(apk, info) % PAGE:
                problems.append("stored uncompressed but not 16 KB zip-aligned")
            if problems:
                failures += 1
                print(f"FAIL {info.filename}: {'; '.join(problems)}")
            else:
                print(f"ok   {info.filename}")
    if checked == 0:
        print(f"no 64-bit native libraries in {path}")
    if failures:
        print(f"{failures} of {checked} 64-bit native libraries are not 16 KB-compatible")
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
