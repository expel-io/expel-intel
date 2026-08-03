#!/usr/bin/env python3
"""
Standalone adaptation of the Xiao Yi's IDAPython string decryptor. Source: https://www.ctfiot.com/286193.html

Scans the Golden Gh0st RAT payload for all
CALL 0x1000148E sites, walks back up to 5 instructions to find PUSH imm32
arguments, then XOR-decrypts those strings using the key at 0x10046160.
"""

import struct
import sys
from pathlib import Path


IMAGE_BASE   = 0x10000000
TARGET_VA    = 0x1000148E   # function that consumes encrypted strings
KEY_VA       = 0x10046160   # XOR key location


# --- PE helpers -----------------------------------------------------------

def load_pe(path):
    data = Path(path).read_bytes()
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    opt_sz = struct.unpack_from('<H', data, pe_off + 20)[0]
    n_sec  = struct.unpack_from('<H', data, pe_off + 6)[0]
    sec_base = pe_off + 24 + opt_sz
    sections = []
    for i in range(n_sec):
        s = data[sec_base + i * 40 : sec_base + i * 40 + 40]
        sections.append({
            'name':   s[:8].rstrip(b'\x00').decode('ascii', errors='replace'),
            'va':     struct.unpack_from('<I', s, 12)[0],
            'vsize':  struct.unpack_from('<I', s,  8)[0],
            'rawoff': struct.unpack_from('<I', s, 20)[0],
            'rawsz':  struct.unpack_from('<I', s, 16)[0],
        })
    return data, sections


def va_to_off(va, sections):
    rva = va - IMAGE_BASE
    for s in sections:
        end = s['va'] + max(s['vsize'], s['rawsz'])
        if s['va'] <= rva < end:
            return s['rawoff'] + (rva - s['va'])
    return None


def read_va(data, sections, va, n):
    off = va_to_off(va, sections)
    if off is None:
        return None
    return data[off : off + n]


# --- Key and string readers -----------------------------------------------

def read_key(data, sections, key_va):
    off = va_to_off(key_va, sections)
    if off is None:
        return b''
    key = bytearray()
    for b in data[off : off + 1024]:
        if b == 0:
            break
        key.append(b)
    return bytes(key)


def read_enc_string(data, sections, ptr_va):
    off = va_to_off(ptr_va, sections)
    if off is None:
        return None
    result = bytearray()
    for b in data[off : off + 1024]:
        if b == 0:
            break
        result.append(b)
    return bytes(result)


def xor_decrypt(enc, key):
    if not key:
        return enc
    if len(key) == 1:
        return bytes(b ^ key[0] for b in enc)
    return bytes(enc[i] ^ key[i % len(key)] for i in range(len(enc)))


# --- CALL scanner ---------------------------------------------------------

def find_call_sites(data, sections, target_va):
    """
    Scan .text for direct CALL instructions (E8 rel32) targeting target_va.
    Returns list of (call_file_offset, call_va).
    """
    text = next((s for s in sections if s['name'] == '.text'), None)
    if not text:
        return []

    raw = data[text['rawoff'] : text['rawoff'] + text['rawsz']]
    target_rva = target_va - IMAGE_BASE
    sites = []

    for i in range(len(raw) - 4):
        if raw[i] != 0xE8:
            continue
        rel32 = struct.unpack_from('<i', raw, i + 1)[0]
        call_va = IMAGE_BASE + text['va'] + i
        dest_va = call_va + 5 + rel32
        if dest_va == target_va:
            sites.append((text['rawoff'] + i, call_va))

    return sites


# --- Walk backwards for PUSH imm32 ----------------------------------------

def find_push_before_call(data, call_off, max_steps=5):
    """
    Walk backwards from call_off looking for PUSH imm32 (0x68 xx xx xx xx).
    Returns list of VA immediates found within max_steps * 10 bytes.
    """
    results = []
    # Search the 50 bytes before the CALL for 0x68 opcodes
    search_start = max(0, call_off - 50)
    window = data[search_start : call_off]
    for i in range(len(window) - 4):
        if window[i] == 0x68:
            imm32 = struct.unpack_from('<I', window, i + 1)[0]
            # sanity-check: should look like a VA in this module
            if IMAGE_BASE <= imm32 < IMAGE_BASE + 0x60000:
                results.append(imm32)
    return results


# --- Main -----------------------------------------------------------------

def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('stage_manual_upack.bin')
    data, sections = load_pe(path)

    key = read_key(data, sections, KEY_VA)
    print(f'XOR key ({len(key)} bytes): {key.hex()}')
    print()

    call_sites = find_call_sites(data, sections, TARGET_VA)
    print(f'Found {len(call_sites)} CALL sites targeting 0x{TARGET_VA:08X}')
    print()

    seen = set()
    results = []

    for call_off, call_va in call_sites:
        pushes = find_push_before_call(data, call_off)
        for ptr_va in pushes:
            if ptr_va in seen:
                continue
            seen.add(ptr_va)
            enc = read_enc_string(data, sections, ptr_va)
            if not enc:
                continue
            dec = xor_decrypt(enc, key)
            try:
                text = dec.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    text = dec.decode('utf-16-le').rstrip('\x00')
                except Exception:
                    text = repr(dec)
            results.append((call_va, ptr_va, enc, dec, text))
            print(f'  CALL @ 0x{call_va:08X}  PUSH ptr=0x{ptr_va:08X}')
            print(f'    enc: {enc.hex()}')
            print(f'    dec: {text}')
            print()

    print(f'--- {len(results)} unique strings decrypted ---')


if __name__ == '__main__':
    main()
