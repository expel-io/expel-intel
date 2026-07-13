#!/usr/bin/env python3
"""
TASLoginBase.dll / TASLogin.log → stage-3 Golden Gh0st RAT PE extractor
=====================================================================
Statically decrypts and LZNT1-decompresses the Golden Gh0st RAT payload
staged in TASLogin.log, using the config struct embedded in the
decrypted blob by TASLoginBase.dll's GetObjectLog loader.

Confirmed working against:
    TASLogin.log (SHA256 encrypted: dd44dabf...)
    TASLoginBase.dll (SHA256: 1abffe97...)
Stage-3 output (verified 2026-07-05): SHA256 990aaa749efe047da57101315a49bcc94e1f6879ae9d05e6a193669a4ef4af28
    (matches the "well-formed" VirusTotal variant of this Golden Gh0st RAT/APT-Q-27 build)

Usage:
    python3 extract_tasloginbase_payload.py <TASLogin.log> [--out-dir ./output]

Outputs:
    <out_dir>/tas_decrypted.bin   — raw decrypted blob (shellcode stub + config + compressed data)
    <out_dir>/tas_stage3.bin      — LZNT1-decompressed stage-3 PE (Golden Gh0st RAT core, VMProtect-protected)
    (+ SHA256 report and C2/key extraction to stdout)
"""

import sys, os, struct, hashlib, argparse

try:
    import lznt1
except ImportError:
    sys.exit("[!] lznt1 not installed — run: pip3 install lznt1 --break-system-packages")


# ── Known constants (version fingerprint) ─────────────────────────────────────

# TASLoginBase.dll cipher (same as crashreport.dll/NvBackend): (byte + 0x77) ^ 0x62
CIPHER_ADD = 0x77
CIPHER_XOR = 0x62

# Config struct offsets in decrypted blob (base derived from JMP target 0x44b + call delta):
STRUCT_OFFSET     = 0x4FE   # byte offset of config struct in decrypted blob
FN_OFFSET_FIELD   = 0x01    # [+0x01] DWORD: offset from struct to decompressor fn (expected 0x75 -> fn at 0x573)
ALLOC_SIZE_FIELD  = 0x05    # [+0x05] DWORD: expected decompressed PE size
SRC_SIZE_FIELD    = 0x09    # [+0x09] DWORD: compressed data byte count
DATA_OFFSET_FIELD = 0x0d    # [+0x0d] DWORD: offset from struct to compressed data (expected 0x1e5 -> data at 0x6E3)

# Known key/C2 offsets inside the decompressed stage-3 PE
KEY_OFFSET = 0x1ee65   # REGISTER_KEY (32B) followed immediately by MODULE_KEY (32B)
C2_OFFSET  = 0x19a410  # cleartext "IP|#PORT|+IP|#PORT|" config string in .rdata

# Reference hashes (TASLogin.log sample, confirmed 2026-07-05)
REF_STAGE3_SHA256 = "990aaa749efe047da57101315a49bcc94e1f6879ae9d05e6a193669a4ef4af28"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decrypt(data: bytes) -> bytes:
    return bytes(((b + CIPHER_ADD) & 0xFF) ^ CIPHER_XOR for b in data)


def check_jmp_at_zero(blob: bytes) -> int | None:
    """Return JMP target offset if blob[0] is a rel32 JMP, else None."""
    if blob[0] != 0xE9:
        return None
    rel = struct.unpack_from("<i", blob, 1)[0]
    return 5 + rel


def read_struct_fields(blob: bytes) -> dict:
    base = STRUCT_OFFSET
    fn_off   = struct.unpack_from("<I", blob, base + FN_OFFSET_FIELD)[0]
    alloc_sz = struct.unpack_from("<I", blob, base + ALLOC_SIZE_FIELD)[0]
    src_sz   = struct.unpack_from("<I", blob, base + SRC_SIZE_FIELD)[0]
    data_off = struct.unpack_from("<I", blob, base + DATA_OFFSET_FIELD)[0]
    return {
        "fn_abs":       base + fn_off,
        "data_abs":     base + data_off,
        "alloc_size":   alloc_sz,
        "src_size":     src_sz,
        "fn_off_raw":   fn_off,
        "data_off_raw": data_off,
    }


def main():
    ap = argparse.ArgumentParser(description="TASLoginBase.dll / TASLogin.log stage-3 extractor")
    ap.add_argument("tas_log", help="Path to TASLogin.log (encrypted)")
    ap.add_argument("--out-dir", default="./output", help="Output directory (default: ./output)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    enc = open(args.tas_log, "rb").read()

    print(f"[*] Input:      {args.tas_log}")
    print(f"[*] Size:       {len(enc):,} bytes")
    print(f"[*] SHA256 enc: {sha256(enc)}")
    print()

    # ── Step 1: decrypt ──────────────────────────────────────────────────────
    blob = decrypt(enc)
    dec_path = os.path.join(args.out_dir, "tas_decrypted.bin")
    open(dec_path, "wb").write(blob)
    print(f"[1] Decrypted (byte+{CIPHER_ADD:#x})^{CIPHER_XOR:#x} -> {dec_path}")

    jmp_target = check_jmp_at_zero(blob)
    if jmp_target is None:
        print(f"    [!] CHANGE DETECTED: blob[0] = 0x{blob[0]:02x} (expected 0xE9 JMP)")
    else:
        print(f"    JMP at 0x0 -> 0x{jmp_target:x}", end="")
        print("  (matches reference)" if jmp_target == 0x44b else "  [!] CHANGED from expected 0x44b")

    # ── Step 2: read config struct ───────────────────────────────────────────
    f = read_struct_fields(blob)
    print(f"    Config struct @ 0x{STRUCT_OFFSET:x}:")
    print(f"      decompressor fn:  blob[0x{f['fn_abs']:x}]  (offset +0x{f['fn_off_raw']:x})",
          "" if f['fn_abs'] == 0x573 else "  [!] CHANGED from 0x573")
    print(f"      alloc_size:       0x{f['alloc_size']:x} ({f['alloc_size']:,}B)")
    print(f"      compressed_size:  0x{f['src_size']:x} ({f['src_size']:,}B)")
    print(f"      data start:       blob[0x{f['data_abs']:x}]  (offset +0x{f['data_off_raw']:x})",
          "" if f['data_abs'] == 0x6E3 else "  [!] CHANGED from 0x6E3")

    # ── Step 3: LZNT1 decompress ─────────────────────────────────────────────
    compressed = blob[f['data_abs']:f['data_abs'] + f['src_size']]
    try:
        stage3 = lznt1.decompress(compressed)
    except Exception as e:
        sys.exit(f"[!] LZNT1 decompression failed: {e}")

    stage3_path = os.path.join(args.out_dir, "tas_stage3.bin")
    open(stage3_path, "wb").write(stage3)
    stage3_hash = sha256(stage3)
    print(f"\n[2] LZNT1 decompressed: {len(stage3):,}B -> {stage3_path}")
    print(f"    SHA256: {stage3_hash}", end="")
    if stage3_hash == REF_STAGE3_SHA256:
        print("  MATCHES reference stage-3 PE")
    else:
        print(f"\n    [!] CHANGED from reference {REF_STAGE3_SHA256}")
        print("         -> payload may have been updated, or extraction offsets shifted")

    if stage3[:2] != b"MZ":
        print(f"    [!] Does not start with MZ -- first bytes: {stage3[:4].hex()}")
        return

    # ── Step 4: pull REGISTER_KEY / MODULE_KEY and C2 config, if offsets hold ──
    print(f"\n[3] Config extraction from stage-3 PE:")
    if len(stage3) >= KEY_OFFSET + 64:
        register_key = stage3[KEY_OFFSET:KEY_OFFSET + 32]
        module_key   = stage3[KEY_OFFSET + 32:KEY_OFFSET + 64]
        print(f"    REGISTER_KEY @0x{KEY_OFFSET:x}: {register_key.hex()}")
        print(f"    MODULE_KEY   @0x{KEY_OFFSET+32:x}: {module_key.hex()}")
    else:
        print(f"    [!] stage-3 too small for key offset 0x{KEY_OFFSET:x}")

    if len(stage3) >= C2_OFFSET + 64:
        c2_region = stage3[C2_OFFSET:C2_OFFSET + 64]
        print(f"    C2 config @0x{C2_OFFSET:x}: {c2_region}")
    else:
        print(f"    [!] stage-3 too small for C2 offset 0x{C2_OFFSET:x}")


if __name__ == "__main__":
    main()
