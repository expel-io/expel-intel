#!/usr/bin/env python3
"""
Golden Gh0st RAT updat.log → inner PE extractor
============================================
Decrypts, LZNT1-decompresses, and UPX-unpacks the Golden Gh0st RAT payload
from an updat.log file captured from the yynewyy / GCS staging chain.

Confirmed working against: updat.log (SHA256 encrypted: 3313f347...)
Inner PE (unpacked): 81e276aa... = windui.dll (April + May 2026)

Usage:
    python3 extractJune2026_NvBackend_log_payload.py <updat.log> [--out-dir ./output]

Outputs:
    <out_dir>/zs_decrypted.bin      — raw decrypted blob (162,744B in known sample)
    <out_dir>/zs_lznt1.bin          — LZNT1-decompressed PE (UPX-packed)
    <out_dir>/zs_unpacked.bin       — final UPX-unpacked PE
    (+ SHA256 report to stdout)

Version-change indicators printed on every run so operator can detect
when APT-Q-27 updates the payload or loader.
"""

import sys, os, struct, hashlib, subprocess, tempfile, shutil, argparse

try:
    import lznt1
except ImportError:
    sys.exit("[!] lznt1 not installed — run: pip3 install lznt1 --break-system-packages")


# ── Known constants (version fingerprint) ─────────────────────────────────────

# crashreport.dll cipher: (byte + 0x77) ^ 0x62
CIPHER_ADD  = 0x77
CIPHER_XOR  = 0x62

# Loader struct offsets in decrypted blob (from config struct base):
# Struct base = blob[0x4FE] (derived: JMP→0x44b, CALL-DELTA subtract=0x12f10bd, add=0x12f14fe, net=0x4FE from entry+5)
STRUCT_OFFSET   = 0x4FE   # byte offset of config struct in decrypted blob
FN_OFFSET_FIELD = 0x01    # [+0x01] DWORD: offset from struct to decompressor fn (expected 0x75 → fn at 0x573)
ALLOC_SIZE_FIELD = 0x05   # [+0x05] DWORD: expected decompressed PE size
SRC_SIZE_FIELD  = 0x09    # [+0x09] DWORD: compressed data byte count
DATA_OFFSET_FIELD = 0x0d  # [+0x0d] DWORD: offset from struct to compressed data (expected 0x1e5 → data at 0x6E3)

# Hash algo multiplier used by custom GetProcAddress (h = h*MUL + signed_byte, &0x7FFFFFFF)
HASH_MULTIPLIER = 0x83

# LZNT1 decompression format constant
LZNT1_FORMAT = 0x102  # COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD

# Reference hashes (April + May 2026 — same binary)
REF_LZNT1_SHA256   = "54e3de897abb9b9b98aeef74bcde785f6f5928f0f2806dd93152a2382f3349dc"
REF_UNPACKED_SHA256 = "81e276aaa3eb9b3f595663c316b3c6414cc3dde5e6cc3a82856b7276acabb7de"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decrypt(data: bytes) -> bytes:
    return bytes(((b + CIPHER_ADD) ^ CIPHER_XOR) & 0xFF for b in data)


def read_struct_fields(blob: bytes) -> dict:
    base = STRUCT_OFFSET
    fn_off   = struct.unpack_from("<I", blob, base + FN_OFFSET_FIELD)[0]
    alloc_sz = struct.unpack_from("<I", blob, base + ALLOC_SIZE_FIELD)[0]
    src_sz   = struct.unpack_from("<I", blob, base + SRC_SIZE_FIELD)[0]
    data_off = struct.unpack_from("<I", blob, base + DATA_OFFSET_FIELD)[0]
    return {
        "fn_abs":       base + fn_off,      # absolute offset of decompressor fn
        "data_abs":     base + data_off,    # absolute offset of compressed payload
        "alloc_size":   alloc_sz,           # expected decompressed size
        "src_size":     src_sz,             # compressed data size
        "fn_off_raw":   fn_off,
        "data_off_raw": data_off,
    }


def check_jmp_at_zero(blob: bytes) -> int | None:
    """Return JMP target offset if blob[0] is a rel32 JMP, else None."""
    if blob[0] != 0xE9:
        return None
    rel = struct.unpack_from("<i", blob, 1)[0]
    return 5 + rel


def upx_unpack(packed_path: str, out_path: str) -> bool:
    r = subprocess.run(
        ["upx", "-d", "-o", out_path, packed_path],
        capture_output=True
    )
    return r.returncode == 0


def main():
    ap = argparse.ArgumentParser(description="Golden Gh0st RAT updat.log extractor")
    ap.add_argument("updat_log", help="Path to updat.log (encrypted)")
    ap.add_argument("--out-dir", default="./output", help="Output directory (default: ./output)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    enc = open(args.updat_log, "rb").read()

    print(f"[*] Input:      {args.updat_log}")
    print(f"[*] Size:       {len(enc):,} bytes")
    print(f"[*] SHA256 enc: {sha256(enc)}")
    print()

    # ── Step 1: decrypt ──────────────────────────────────────────────────────
    blob = decrypt(enc)
    dec_path = os.path.join(args.out_dir, "zs_decrypted.bin")
    open(dec_path, "wb").write(blob)
    print(f"[1] Decrypted ({CIPHER_ADD:#x}+byte)^{CIPHER_XOR:#x} → {dec_path}")

    # Version-change check: JMP at offset 0
    jmp_target = check_jmp_at_zero(blob)
    if jmp_target is None:
        print(f"    [!] CHANGE DETECTED: blob[0] = 0x{blob[0]:02x} (expected 0xE9 JMP)")
    else:
        print(f"    JMP at 0x0 → 0x{jmp_target:x}", end="")
        if jmp_target != 0x44b:
            print(f"  [!] CHANGED from expected 0x44b — loader may have moved")
        else:
            print("  (matches reference)")

    # ── Step 2: read config struct ───────────────────────────────────────────
    fields = read_struct_fields(blob)
    print(f"    Config struct @ 0x{STRUCT_OFFSET:x}:")
    print(f"      decompressor fn:   blob[0x{fields['fn_abs']:x}]  (offset +0x{fields['fn_off_raw']:x})", end="")
    print("" if fields['fn_abs'] == 0x573 else "  [!] CHANGED from 0x573")
    print(f"      alloc_size:        0x{fields['alloc_size']:x} ({fields['alloc_size']:,}B)", end="")
    print("" if fields['alloc_size'] == 0x28000 else f"  [!] CHANGED from 0x28000")
    print(f"      compressed_size:   0x{fields['src_size']:x} ({fields['src_size']:,}B)")
    print(f"      data start:        blob[0x{fields['data_abs']:x}]  (offset +0x{fields['data_off_raw']:x})", end="")
    print("" if fields['data_abs'] == 0x6E3 else "  [!] CHANGED from 0x6E3")

    # ── Step 3: LZNT1 decompress ─────────────────────────────────────────────
    compressed = blob[fields['data_abs']:]
    try:
        decompressed = lznt1.decompress(compressed)
    except Exception as e:
        sys.exit(f"[!] LZNT1 decompression failed: {e}")

    lznt1_path = os.path.join(args.out_dir, "zs_lznt1.bin")
    open(lznt1_path, "wb").write(decompressed)
    lznt1_hash = sha256(decompressed)
    print(f"\n[2] LZNT1 decompressed: {len(decompressed):,}B → {lznt1_path}")
    print(f"    SHA256: {lznt1_hash}", end="")
    if lznt1_hash == REF_LZNT1_SHA256:
        print("  ✓ MATCHES reference (same packed PE)")
    else:
        print(f"\n    [!] CHANGED from reference {REF_LZNT1_SHA256}")
        print("         → APT-Q-27 may have updated the Golden Gh0st RAT payload")

    # Quick PE check
    if decompressed[:2] != b"MZ":
        print(f"    [!] Does not start with MZ — first bytes: {decompressed[:4].hex()}")
    else:
        e_lfanew = struct.unpack_from("<I", decompressed, 0x3c)[0]
        print(f"    MZ OK, e_lfanew=0x{e_lfanew:x}", end="")
        if e_lfanew + 2 <= len(decompressed) and decompressed[e_lfanew:e_lfanew+2] == b"PE":
            print("  PE sig valid")
        else:
            print("  (PE sig not at e_lfanew — UPX-packed header expected)")

    # ── Step 4: UPX unpack ───────────────────────────────────────────────────
    upx_out = os.path.join(args.out_dir, "zs_unpacked.bin")
    print(f"\n[3] UPX unpack → {upx_out}")
    if not shutil.which("upx"):
        print("    [!] upx not found in PATH — skipping unpack step")
        upx_hash = None
    else:
        if upx_unpack(lznt1_path, upx_out):
            pe = open(upx_out, "rb").read()
            upx_hash = sha256(pe)
            print(f"    Unpacked: {len(pe):,}B")
            print(f"    SHA256:   {upx_hash}", end="")
            if upx_hash == REF_UNPACKED_SHA256:
                print("  ✓ MATCHES windui.dll reference (same payload, no update)")
            else:
                print(f"\n    [!] CHANGED from reference {REF_UNPACKED_SHA256}")
                print("         → APT-Q-27 has updated the Golden Gh0st RAT DLL")
        else:
            print("    [!] upx -d failed — binary may not be UPX-packed in this version")
            upx_hash = None

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("VERSION COMPARISON SUMMARY")
    print("=" * 60)
    print(f"  Cipher (add/xor):    0x{CIPHER_ADD:02x} / 0x{CIPHER_XOR:02x}   [check if decryption fails]")
    print(f"  Hash algo mult:      0x{HASH_MULTIPLIER:02x}           [check if loader changed]")
    print(f"  Compression:         LZNT1 (0x{LZNT1_FORMAT:x})    [check if algorithm changed]")
    print(f"  LZNT1 SHA256 match:  {'YES' if lznt1_hash == REF_LZNT1_SHA256 else 'NO  <-- UPDATED PE'}")
    if upx_hash:
        print(f"  Unpacked SHA256 match: {'YES (windui.dll unchanged)' if upx_hash == REF_UNPACKED_SHA256 else 'NO  <-- UPDATED DLL'}")
    print()
    print("Reference hashes (April + May 2026):")
    print(f"  Packed:   {REF_LZNT1_SHA256}")
    print(f"  Unpacked: {REF_UNPACKED_SHA256}")


if __name__ == "__main__":
    main()
