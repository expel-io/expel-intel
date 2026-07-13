#!/usr/bin/env python3
"""
Golden Gh0st RAT (APT-Q-27) PCAP Analyzer
==========================================
Decrypts and extracts data from traffic captures to the Golden Gh0st RAT
WebSocket C2 (uu.goldeyeuu.io:5188, IP 13.158.37.189).

Two modes:
  summary  — victim fingerprint, timeline, file listing, C2 operation log
  extract  — saves screenshots as PNG and file listings as text to disk
  both     — runs summary then extract

Usage:
  python3 gg_pcap_analyzer.py --pcap FILE [--mode summary|extract|both]
                               [--out-dir DIR] [-v]

Requires: tshark, Pillow (PIL)
Protocol reference: windui.dll SHA256 81e276aa... / gg_emulator.py
"""

import argparse
import datetime
import os
import re
import struct
import subprocess
import sys
import zlib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

# ── Crypto ────────────────────────────────────────────────────────────────────

REGISTER_KEY = bytes.fromhex(
    "8A913610E905C3DD1F657811EA3B1933"
    "471B230F88E1C155616099A03AB0ABC0"
)
MODULE_KEY = bytes.fromhex(
    "2031A71C399563ADAF1572E10ABB3953"
    "87EB132208A001C5E140496D7A3E0B26"
)

# ── Server command dispatch table ──────────────────────────────────────────────
# session_id field (bytes 8-11) of S2C frames is the command ID.
# Sources: windui.dll static analysis (April/May 2026) + xz.aliyun.com/news/90793
# article on APT-Q-27 campaign with DataReport.dll loader.
# NOTE: article's article uses command codes that are off by ±1 from what is observed
# in the uu.goldeyeuu.io:5188 PCAP (e.g. article 0x1565=DllScreen; PCAP observes
# 0x1566 for HiDPI screen capture; article 0x1574=DllKeybo; PCAP observes 0x1573
# preceding screenshot responses). This is a minor versioning difference between builds.
SERVER_CMD_TABLE = {
    # -- Plugin payload delivery ───────────────────────────────────────────────
    0x0C8B: "SRV_PAYLOAD_BEGIN",        # Plugin push notification; preceeds chunk delivery
    0x0C8C: "SRV_PAYLOAD_CHUNK",        # Plugin payload chunk (cipher2/MODULE_KEY)
    # ── Session management ──────────────────────────────────────────────────
    0x1536: "SRV_KEEPALIVE_ACK",        # Heartbeat ACK
    # ── File system operations ──────────────────────────────────────────────
    0x1537: "SRV_DLLFILE",              # DllFile — file operations plugin
    0x1538: "SRV_DIR_PATH",             # Directory path; triggers client file listing
    # ── Screen capture ──────────────────────────────────────────────────────
    0x1565: "SRV_DLLSCREEN",            # DllScreen — standard screenshot trigger
    0x1566: "SRV_DLLSCREEN_HIDPI",      # HiDPI/4K screenshot variant (+1 from 0x1565)
    0x154C: "SRV_DLLSCREEN_HIDE",       # DllScreenHide — screenshot with display blanked
    # 0x1573: precedes standard screenshots in PCAP; not in windui.dll dispatch table —
    # likely a server-side sequencing command or present in a newer implant build.
    0x1573: "SRV_SCREENSHOT_TRIGGER",   # Precedes every standard screenshot in this PCAP
    0x1574: "SRV_DLLKEYBO",             # DllKeyboard — keylogging activation
    # ── Payload drop / execute ──────────────────────────────────────────────
    0x1590: "SRV_DROP_EXE_0",           # Write + execute file (variant 0)
    0x1591: "SRV_DROP_EXE_1",           # Write + execute file (variant 1)
    0x1592: "SRV_DROP_LOG",             # Drop Plugin.log
    # ── Credential collection ────────────────────────────────────────────────
    # Confirmed by decompilation of sub_1001b144 → sub_1001f24d → sub_1001b79c.
    # These trigger credential collection via CDllManager module cmd 0x987.
    0x0C8A: "SRV_CRED_COLLECT_0",       # Credential collection (primary trigger; type 0)
    0x098F: "SRV_CRED_COLLECT_1",       # Credential collection (alt trigger; type 1)
    0x0990: "SRV_CRED_COLLECT_2",       # Credential collection (alt trigger; type 2)
    # Direct credential type handlers — each is a 10-byte stub calling a dedicated
    # target function. Pattern: kill target process, wait Sleep(2-3s), read credential
    # files, exfiltrate.
    0x0C9B: "SRV_CRED_RUNDLL32",        # Elevated RunDll32 — ShellExecuteA("runas","RunDll32.exe",...); likely credential-dumping DLL
    0x0C9C: "SRV_CRED_SKYPE",           # Skype — reads Local Storage login tokens from %APPDATA%; kills skype.exe first
    0x0C9D: "SRV_CRED_CHROME",          # Chrome — reads User Data/Login Data from %LOCALAPPDATA%; kills Chrome.exe first
    0x0C9E: "SRV_CRED_FIREFOX",         # Firefox — reads profile from %APPDATA%; kills firefox.exe first
    0x0C9F: "SRV_CRED_360SE",           # 360 Secure Browser — reads Default\apps from %APPDATA%; kills 360se.exe first
    0x0CA0: "SRV_CRED_360CHROME",       # 360 Speed Browser — reads profile from %LOCALAPPDATA%; kills 360chrome.exe first
    0x0CA1: "SRV_CRED_MULTIAPP",        # Multi-app sweep — 8 profile paths; avBackup.dat/FormData3.dat/historyUrl3.db (Tencent QQ / Chinese apps)
    0x0CA2: "SRV_CRED_QQBROWSER",       # Tencent QQ Browser — reads Default profile from %LOCALAPPDATA%; kills QQBrowser.exe first
    0x0991: "SRV_ONBOOTUP",             # onBootup — boot-time config / notification plugin
    # ── Remote shell / execution ────────────────────────────────────────────
    0x1589: "SRV_DLLSHELL",             # DllShell — interactive shell
    0x158F: "SRV_RUN_PROGRAM",          # Run specified program via CreateProcessA on WinSta0\Default
    0x1593: "SRV_OPENURL_HIDE",         # DllOpenURLHIDE — open URL in hidden browser window
    0x1594: "SRV_OPENURL_SHOW",         # DllOpenURLSHOW — open URL in visible browser window
    # ── System / process management ─────────────────────────────────────────
    0x1579: "SRV_DLLSYSTEM",            # DllSystem — system information collection
    0x1587: "SRV_DLLMSGBOX",            # DllMsgBox — display message box on victim screen
    0x1597: "SRV_DLLSERSTART",          # DllSerStart — service/server start (purpose unclear)
    0x0C91: "SRV_FNPROXY",              # fnProxy — SOCKS/TCP proxy tunnel start
    0x0C8E: "SRV_UNK_C8E",              # Unresolved — Malcat cannot decompile VA 0x10014b55; needs Ghidra
    0x0C8F: "SRV_RUNAS",                # UAC bypass — re-launches self via ShellExecuteExA("runas") then exits
    0x0C90: "SRV_KILL_EXPLORER",        # Terminate explorer.exe
    0x0C95: "SRV_KILL_PROCESS",         # Terminate named process (name from payload); reports kill count to C2
    0x0C96: "SRV_DELETE_PATH",          # Recursive file/directory delete (path from payload)
    0x0C97: "SRV_WATCHDOG_CHECK",       # Watchdog health check — re-invokes watchdog BAT generator if cmd.exe absent
    0x0C98: "SRV_UNK_C98",              # Unresolved — likely credential setup stub; needs Ghidra at VA 0x1001cc0c
    0x0C99: "SRV_LIST_PROCESSES",       # Enumerate all processes with full image paths via GetProcessImageFileNameA
    # ── Live C2 re-targeting ─────────────────────────────────────────────────
    # These allow the operator to pivot infrastructure without redeployment.
    0x098E: "SRV_UPDATE_C2_PORT",       # Update C2 SOCKS port (ConnSocks key); busy-waits until reconnect completes
    0x1595: "SRV_UPDATE_C2_HOST",       # Update C2 hostname/IP (Host key)
    0x1588: "SRV_CONNECTGROUP",         # Update session routing group (ConnectGroup key)
    0x15AC: "SRV_TCP_RECONNECT",        # Sets reconnect flag [0x56e]='y' then calls CTcpClient.#52
    0x156F: "SRV_TCP_OP_156F",          # CTcpClient.#52 TCP client operation (shares handler with 0x1578)
    0x1578: "SRV_TCP_OP_1578",          # CTcpClient.#52 TCP client operation (shares handler with 0x156F)
    # ── Cleanup / exit ──────────────────────────────────────────────────────
    0x158A: "SRV_UNK_158A",             # Purpose not yet determined (sub_1001ca5f)
    0x158B: "SRV_SELF_DESTRUCT",        # Self-destruct — deletes 3 payload files, cleans registry persistence, ExitProcess
    0x158C: "SRV_WIPE_EVTLOGS",         # Windows Event Log wiper — clears Application, Security, System logs
    # ── Observed but not yet attributed ─────────────────────────────────────
    0x1569: "SRV_UNK_1569",             # 28-byte extended command (May 2026 PCAP; absent from this DLL build)
}


def _cipher1(data: bytes, key: bytes, decrypt: bool) -> bytes:
    """sub_10001ade: op = i % 8, 32-byte key cycle."""
    result = bytearray(data)
    sign = -1 if decrypt else 1
    for i, k in ((i, key[i % 32]) for i in range(len(result))):
        op = i % 8
        if op == 0:
            result[i] ^= k
        elif op == 1:
            result[i] = (result[i] + sign * (k >> 1)) & 0xFF
        elif op == 2:
            result[i] = (result[i] - sign * (k * 4)) & 0xFF
        elif op == 3:
            result[i] = (result[i] + sign * (k << 2)) & 0xFF
    return bytes(result)


def _cipher2(data: bytes, key: bytes, decrypt: bool) -> bytes:
    """sub_10001ba6: op = i % 6, 32-byte key cycle.
    decrypt=True  → subtract for op 0,1; add for op 3
    decrypt=False → add for op 0,1; subtract for op 3  (encrypt/reverse direction)
    """
    result = bytearray(data)
    sign = 1 if decrypt else -1
    for i, k in ((i, key[i % 32]) for i in range(len(result))):
        op = i % 6
        if op == 0:
            result[i] = (result[i] - sign * (k >> 2)) & 0xFF
        elif op == 1:
            result[i] = (result[i] - sign * (k * 2)) & 0xFF
        elif op == 2:
            if i > 0:
                result[i] ^= (k % i + k * 4 + i) & 0xFF
        elif op == 3:
            result[i] = (result[i] + sign * (k * 2)) & 0xFF
    return bytes(result)


def _cipher2_at_rest_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt a cipher2/MODULE_KEY at-rest plugin blob (windui.dll sub_10001ba6).
    Confirmed working: produces valid MZ PE header from windui_assembled.bin.
    op=i%6: 0→sub(k>>2), 1→sub(k*2), 2→XOR(k%i+k*4+i) [i>0], 3→add(k*2).
    """
    buf = bytearray(data)
    for i in range(len(buf)):
        op = i % 6
        k = key[i & 0x1F]
        if op == 0:
            buf[i] = (buf[i] - (k >> 2)) & 0xFF
        elif op == 1:
            buf[i] = (buf[i] - (k * 2)) & 0xFF
        elif op == 2:
            if i > 0:
                buf[i] ^= (k % i + k * 4 + i) & 0xFF
        elif op == 3:
            buf[i] = (buf[i] + (k * 2)) & 0xFF
    return bytes(buf)


def _assemble_plugin_payload(chunks: List[bytes]) -> bytes:
    """Assemble SRV_PAYLOAD_CHUNK plaintext pieces into the at-rest cipher2 blob.

    After cipher1+zlib transport-layer stripping each chunk carries:
      [file_offset(4 LE)][chunk_data_len(4 LE)][chunk_data...]
    Sort by file_offset and write into a contiguous buffer.
    """
    CHUNK_HDR = 8
    pieces = []
    for chunk in chunks:
        if len(chunk) < CHUNK_HDR:
            continue
        file_offset = struct.unpack_from("<I", chunk, 0)[0]
        data = chunk[CHUNK_HDR:]
        pieces.append((file_offset, data))
    if not pieces:
        return b""
    pieces.sort(key=lambda x: x[0])
    total = pieces[-1][0] + len(pieces[-1][1])
    buf = bytearray(total)
    for file_offset, data in pieces:
        buf[file_offset:file_offset + len(data)] = data
    return bytes(buf)


def _try_decompress(data: bytes) -> Optional[bytes]:
    for wbits in (15, -15, 47):
        try:
            return zlib.decompress(data, wbits=wbits)
        except zlib.error:
            pass
    return None


def _is_plausible_raw_beacon(data: bytes) -> bool:
    """Validate raw-decrypted (uncompressed) data as a mini auth beacon."""
    if len(data) < 12:
        return False
    w = struct.unpack_from("<I", data, 4)[0]
    h = struct.unpack_from("<I", data, 8)[0]
    return 640 <= w <= 7680 and 480 <= h <= 4320


def decrypt_payload(data: bytes) -> Tuple[Optional[bytes], str]:
    """
    Try all known key/cipher combinations, compressed and uncompressed.
    Returns (plaintext, description) or (None, "failed").
    """
    candidates = [
        ("cipher1/REGISTER_KEY", lambda d: _try_decompress(_cipher1(d, REGISTER_KEY, True))),
        ("cipher2/MODULE_KEY",   lambda d: _try_decompress(_cipher2(d, MODULE_KEY, True))),
        ("cipher1/MODULE_KEY",   lambda d: _try_decompress(_cipher1(d, MODULE_KEY, True))),
        ("zlib_only",            lambda d: _try_decompress(d)),
    ]
    for name, fn in candidates:
        result = fn(data)
        if result and len(result) >= 4:
            return result, name

    # Raw-cipher fallback for uncompressed frames (e.g. mini auth beacons).
    # Only accepted when the decrypted bytes pass a plausibility check to avoid
    # returning garbage for frames that genuinely failed to decrypt.
    for name, fn in [
        ("cipher1/REGISTER_KEY_raw", lambda d: _cipher1(d, REGISTER_KEY, True)),
        ("cipher2/MODULE_KEY_raw",   lambda d: _cipher2(d, MODULE_KEY, True)),
    ]:
        result = fn(data)
        if result and len(result) >= 4 and _is_plausible_raw_beacon(result):
            return result, name

    return None, "failed"


# ── Protocol parsing ──────────────────────────────────────────────────────────

HEADER_SIZE = 12  # [total_len(4)][orig_plaintext_size(4)][session_id(4)]


@dataclass
class WsFrame:
    frame_num: int
    timestamp: float
    stream: int
    direction: str          # "C2S" or "S2C"
    total_len: int
    orig_size: int
    session_id: int
    payload: bytes          # encrypted bytes after 12-byte header


@dataclass
class VictimInfo:
    os_major: int = 0
    os_minor: int = 0
    os_build: int = 0
    ip_address: str = ""
    hostname: str = ""
    mac_address: str = ""
    timestamp: str = ""

    def os_name(self) -> str:
        build_names = {
            17763: "Windows 10/Server 2019 (Build 17763 / LTSC 1809)",
            18363: "Windows 10 1909 (Build 18363)",
            19041: "Windows 10 2004 (Build 19041)",
            19042: "Windows 10 20H2 (Build 19042)",
            19043: "Windows 10 21H1 (Build 19043)",
            19044: "Windows 10 21H2 (Build 19044)",
            19045: "Windows 10 21H2 (Build 19045)",
            22000: "Windows 11 21H2 (Build 22000)",
            22621: "Windows 11 22H2 (Build 22621)",
            22631: "Windows 11 23H2 (Build 22631)",
        }
        return build_names.get(self.os_build,
               f"Windows {self.os_major}.{self.os_minor} (Build {self.os_build})")


@dataclass
class BeaconInfo:
    screen_width: int = 0
    screen_height: int = 0
    next_exfil_size: int = 0
    palette: List[int] = field(default_factory=list)  # 16 grayscale values


@dataclass
class C2Event:
    frame_num: int
    timestamp: float
    stream: int
    event_type: str   # REGISTER | AUTH_BEACON | SCREENSHOT | FILE_LISTING |
                      # SERVER_PAYLOAD | HEARTBEAT | UNKNOWN
    direction: str
    orig_size: int
    plaintext: Optional[bytes] = None
    cipher_used: str = ""
    note: str = ""


# ── Message classification ────────────────────────────────────────────────────

def _parse_victim_info(plaintext: bytes) -> VictimInfo:
    """Parse OSVERSIONINFOEX (first 284 bytes) + fingerprint fields."""
    info = VictimInfo()
    if len(plaintext) < 20:
        return info
    try:
        _, major, minor, build, _ = struct.unpack_from("<IIIII", plaintext, 0)
        info.os_major = major
        info.os_minor = minor
        info.os_build = build
    except struct.error:
        pass

    # IP address: look for valid private/link-local DWORD anywhere in plaintext
    for i in range(0, len(plaintext) - 3):
        b = plaintext[i:i+4]
        if b[0] in (10, 172, 192) or (b[0] == 169 and b[1] == 254):
            candidate = f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"
            # Prefer non-summary addresses (not x.0.0.0 or x.255.255.255)
            if b[2] != 0 and b[3] not in (0, 255):
                info.ip_address = candidate
                break
        if info.ip_address:
            break

    # Hostname: ASCII alnum+hyphen+underscore string ≥8 chars in bytes 150-220
    host_region = plaintext[150:220]
    for i in range(len(host_region)):
        if 0x20 <= host_region[i] <= 0x7E:
            end = i
            while end < len(host_region) and 0x20 <= host_region[end] <= 0x7E:
                end += 1
            candidate = host_region[i:end].decode("ascii", errors="replace")
            stripped = candidate.replace("-", "").replace("_", "").replace(".", "")
            if len(stripped) >= 4 and stripped.isalnum():
                info.hostname = candidate.strip()
                break

    # Timestamp at offset 286 (C-string "YYYY-MM-DD HH:MM:SS")
    if len(plaintext) > 286:
        ts_end = plaintext.find(b"\x00", 286)
        if ts_end > 286:
            try:
                ts_raw = plaintext[286:ts_end].decode("ascii")
                if re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", ts_raw):
                    info.timestamp = ts_raw
            except UnicodeDecodeError:
                pass

    # MAC: first plausible 6-byte sequence in CSD buffer area (bytes 20-275)
    csd = plaintext[20:276]
    for i in range(len(csd) - 5):
        chunk = csd[i:i+6]
        if (all(b != 0 for b in chunk)
                and len(set(chunk)) >= 4
                and sum(1 for b in chunk if b >= 0x80) >= 1):
            info.mac_address = ":".join(f"{b:02x}" for b in chunk)
            break

    return info


def _parse_beacon(plaintext: bytes) -> BeaconInfo:
    """Parse auth beacon: screen resolution, palette, exfil size."""
    info = BeaconInfo()
    if len(plaintext) < 28:
        return info
    try:
        info.screen_width  = struct.unpack_from("<I", plaintext, 4)[0]
        info.screen_height = struct.unpack_from("<I", plaintext, 8)[0]
        info.next_exfil_size = struct.unpack_from("<I", plaintext, 20)[0]
    except struct.error:
        pass

    # Palette: 15 × [B, B, B, 0x00] RGBX entries starting at offset 44
    palette = []
    for i in range(15):
        off = 44 + i * 4
        if off + 3 < len(plaintext):
            palette.append(plaintext[off])   # grayscale value (R=G=B)
    palette.append(0x00)                      # implicit 16th entry = black
    info.palette = palette
    return info


def _is_valid_beacon(plaintext: bytes) -> bool:
    # Full 104-byte beacon OR 40-byte mini beacon (uncompressed HiDPI variant).
    if len(plaintext) < 12:
        return False
    if len(plaintext) not in (40, 104):
        return False
    w = struct.unpack_from("<I", plaintext, 4)[0]
    h = struct.unpack_from("<I", plaintext, 8)[0]
    return 640 <= w <= 7680 and 480 <= h <= 4320


# Well-known Windows directory names that appear in file listings without separators.
_WIN_FOLDERS = frozenset({
    "Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music",
    "AppData", "ProgramData", "Temp", "Windows", "System32", "SysWOW64",
    "Program Files", "Users", "Roaming", "Local", "LocalLow", "Startup",
    "OneDrive", "Contacts", "Favorites", "Recent", "Searches", "Templates",
    "SendTo", "NetHood", "PrintHood", "Application Data", "Saved Games",
})


def _looks_like_filename(s: str) -> bool:
    """
    Return True if s is plausibly a filename or directory component.

    Requires an explicit filesystem indicator (.ext, path separator, drive letter)
    to avoid false-positives from 4bpp pixel runs like '{9g9g9g9g...' which contain
    printable ASCII letters and digits but are clearly not paths.
    """
    if not s or len(s) < 3:
        return False
    if len(set(s)) < 3:
        return False
    if not any(c.isalnum() for c in s):
        return False
    # Must have at least one unambiguous filesystem indicator.
    if "." in s or "\\" in s or "/" in s or ":" in s:
        return True
    # Known Windows directory names (no separator needed)
    if s.strip() in _WIN_FOLDERS:
        return True
    return False


def _parse_file_listing(plaintext: bytes) -> List[str]:
    """Extract filename strings from null-delimited payload."""
    strings = []
    seen = set()
    for m in re.finditer(rb"[\x20-\x7e]{4,}", plaintext):
        s = m.group().decode("ascii", errors="replace").strip()
        if s not in seen and _looks_like_filename(s):
            strings.append(s)
            seen.add(s)
    return strings


def _classify(frame: WsFrame, last_beacon: Optional[BeaconInfo]) -> Tuple[str, str]:
    """
    Return (event_type, note) for a frame.

    Server→client frames use the session_id (bytes 8-11) as a command ID looked
    up in SERVER_CMD_TABLE.  Raw command frames (orig_size == 0) are not
    encrypted; only large payload-delivery frames (orig_size > 0) are.

    Client→server frames carry the original plaintext size in orig_size and are
    always encrypted+compressed with cipher1/REGISTER_KEY.
    """
    if not frame.payload:
        return "HEARTBEAT", ""

    if frame.orig_size == 0 and len(frame.payload) <= 8:
        return "HEARTBEAT", ""

    # ── Server→Client: decode by command ID (session_id field) ────────────────
    if frame.direction == "S2C":
        cmd_name = SERVER_CMD_TABLE.get(frame.session_id)
        if cmd_name:
            # Large payload-delivery commands still need decryption
            if cmd_name == "SRV_PAYLOAD_CHUNK" and len(frame.payload) > 512:
                plaintext, cipher = decrypt_payload(frame.payload)
                if plaintext:
                    return "SERVER_PAYLOAD", cipher
            return cmd_name, "raw_command"
        # Not in table — try decrypt; if that fails, mark unknown
        if len(frame.payload) > 512:
            plaintext, cipher = decrypt_payload(frame.payload)
            if plaintext:
                return "SERVER_PAYLOAD", cipher
        return "UNKNOWN", f"S2C cmd_id=0x{frame.session_id:04x} {len(frame.payload)}B"

    # ── Client→Server: decrypt + classify by content ──────────────────────────
    plaintext, cipher = decrypt_payload(frame.payload)

    if plaintext is None:
        return "UNKNOWN", f"decrypt failed ({len(frame.payload)} bytes)"

    size = len(plaintext)

    # Registration: exactly 516 bytes, starts with OSVERSIONINFOEX size=284
    if size == 516 and len(plaintext) >= 4:
        sz_field = struct.unpack_from("<I", plaintext, 0)[0]
        if sz_field == 284:
            return "REGISTER", cipher

    # Auth beacon: 40-byte mini (HiDPI/uncompressed) or 104-byte standard.
    # Both have valid screen dimensions at [4:12].
    if _is_valid_beacon(plaintext):
        return "AUTH_BEACON", cipher

    # Screenshot: size == W * H / 2 for standard 4bpp, or 4× that for HiDPI
    # (physical 4K display = 2× logical width × 2× logical height at same 4bpp).
    if last_beacon and last_beacon.screen_width and last_beacon.screen_height:
        expected = (last_beacon.screen_width * last_beacon.screen_height) // 2
        if size == expected:
            return "SCREENSHOT", cipher
        if size == expected * 4:
            return "SCREENSHOT_HIDPI", cipher

    # Screen streaming tile/delta updates: decrypted payload starts with the
    # two-byte marker 0x01 0x01 followed by tile metadata (coordinates + dims).
    # These are continuous screen capture chunks sent in session 0x0966 and must
    # be checked BEFORE the file-listing heuristic to avoid false positives.
    if frame.direction == "C2S" and size >= 12 and plaintext[:2] == b'\x01\x01':
        return "SCREEN_STREAM", cipher

    # File listing: string-dense C2S payload where strings contain filesystem
    # indicators (extension, path separator, drive letter).
    if size >= 256 and frame.direction == "C2S":
        candidates = re.findall(rb"[\x20-\x7e]{6,}", plaintext)
        filename_strings = [
            s for s in candidates
            if _looks_like_filename(s.decode("ascii", errors="replace").strip())
        ]
        total_fn_bytes = sum(len(s) for s in filename_strings)
        if filename_strings and total_fn_bytes / size > 0.15:
            return "FILE_LISTING", cipher

    # Server payload delivery (large server→client chunks)
    if frame.direction == "S2C" and size >= 1000:
        return "SERVER_PAYLOAD", cipher

    return "DATA", cipher


# ── PCAP extraction via tshark ────────────────────────────────────────────────

def extract_ws_frames(pcap_path: str, verbose: bool = False) -> List[WsFrame]:
    """Run tshark and return all decoded WebSocket frames."""
    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "websocket",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "ip.src",
        "-e", "tcp.stream",
        "-e", "websocket.payload_length",
        "-e", "data",
    ]
    if verbose:
        print(f"[tshark] Extracting WebSocket frames from {pcap_path} ...", file=sys.stderr)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print("ERROR: tshark timed out", file=sys.stderr)
        return []
    except FileNotFoundError:
        print("ERROR: tshark not found. Install Wireshark/tshark.", file=sys.stderr)
        return []

    # Detect the C2 server IP from WebSocket upgrade host header
    c2_ip = _detect_c2_ip(pcap_path)

    frames = []
    for raw_line in result.stdout.strip().split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        try:
            frame_num = int(parts[0])
            ts = float(parts[1])
            src_ip = parts[2].strip()
            stream = int(parts[3])
            lengths_str = parts[4].strip()
            payloads_str = parts[5].strip()
        except (ValueError, IndexError):
            continue

        # Handle multiple WebSocket messages per TCP frame (comma-separated)
        length_list = [l.strip() for l in lengths_str.split(",") if l.strip()]
        payload_list = [p.strip() for p in payloads_str.split(",") if p.strip()]

        for idx, pl_hex in enumerate(payload_list):
            try:
                raw = bytes.fromhex(pl_hex)
            except ValueError:
                continue
            if len(raw) < HEADER_SIZE:
                continue

            total_len = struct.unpack_from("<I", raw, 0)[0]
            orig_size = struct.unpack_from("<I", raw, 4)[0]
            session_id = struct.unpack_from("<I", raw, 8)[0]
            payload = raw[HEADER_SIZE:]

            direction = "S2C" if src_ip == c2_ip else "C2S"

            frames.append(WsFrame(
                frame_num=frame_num,
                timestamp=ts,
                stream=stream,
                direction=direction,
                total_len=total_len,
                orig_size=orig_size,
                session_id=session_id,
                payload=payload,
            ))

    if verbose:
        print(f"[tshark] Extracted {len(frames)} WebSocket messages", file=sys.stderr)
    return frames


def _detect_c2_ip(pcap_path: str) -> str:
    """Extract the C2 server IP from the WebSocket 101 response source."""
    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "http.response.code == 101",
        "-T", "fields",
        "-e", "ip.src",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        ips = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        if ips:
            return ips[0]
    except Exception:
        pass
    # Fallback: look for the HTTP GET upgrade
    cmd2 = [
        "tshark", "-r", pcap_path,
        "-Y", 'http.request.method == "GET" and websocket',
        "-T", "fields",
        "-e", "ip.dst",
    ]
    try:
        result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=30)
        ips = [l.strip() for l in result2.stdout.strip().split("\n") if l.strip()]
        if ips:
            return ips[0]
    except Exception:
        pass
    return ""


def _get_ws_info(pcap_path: str) -> Tuple[str, str, str]:
    """Extract host, destination port, and request path from the WebSocket upgrade request."""
    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "http.upgrade",
        "-T", "fields",
        "-e", "http.host",
        "-e", "tcp.dstport",
        "-e", "http.request.uri",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        for line in r.stdout.strip().split("\n"):
            parts = line.strip().split("\t")
            if parts and parts[0].strip():
                host = parts[0].strip()
                port = parts[1].strip() if len(parts) > 1 else ""
                path = parts[2].strip() if len(parts) > 2 else ""
                return host, port, path
    except Exception:
        pass
    return "", "", ""


# ── Screenshot rendering ──────────────────────────────────────────────────────

def render_screenshot(
    raw_4bpp: bytes,
    palette: List[int],
    width: int,
    height: int,
) -> Optional[bytes]:
    """
    Convert 4bpp + 16-color grayscale palette to a corrected PNG (bytes).
    Pixel storage: bottom-to-top rows, right-to-left within each row
    (equivalent to rotate 180° + flip horizontal from raw rendering).
    Correction: numpy vertical flip → correct image.
    """
    try:
        from PIL import Image
        import numpy as np
    except ImportError:
        return None

    if len(raw_4bpp) != width * height // 2:
        return None

    # Expand 4bpp → 8bpp grayscale
    pixels = np.empty(width * height, dtype=np.uint8)
    palette_arr = np.array(palette[:16] + [0] * max(0, 16 - len(palette)), dtype=np.uint8)

    raw = np.frombuffer(raw_4bpp, dtype=np.uint8)
    hi_nibbles = (raw >> 4) & 0x0F
    lo_nibbles = raw & 0x0F
    pixels[0::2] = palette_arr[hi_nibbles]
    pixels[1::2] = palette_arr[lo_nibbles]

    img_arr = pixels.reshape((height, width))

    # Pixel data is stored bottom-to-top with rows reversed; flip vertically.
    # Empirically verified: net transform = rotate(180°) + flip_horizontal = flipud.
    img_arr = np.flipud(img_arr)

    img = Image.fromarray(img_arr, mode="L")

    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


# ── Analysis pipeline ─────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    pcap_path: str
    c2_ip: str = ""
    c2_host: str = ""
    c2_port: str = ""
    c2_path: str = ""
    victim: Optional[VictimInfo] = None
    events: List[C2Event] = field(default_factory=list)
    # (frame_num, timestamp, png_bytes, beacon, rendered_width, rendered_height)
    screenshots: List[Tuple[int, float, bytes, BeaconInfo, int, int]] = field(default_factory=list)
    file_listings: List[Tuple[int, float, List[str]]] = field(default_factory=list)
    server_payloads: List[Tuple[int, float, bytes]] = field(default_factory=list)
    screen_stream_frames: int = 0   # count of tile-update frames (not stored individually)
    decode_errors: int = 0


def analyze(pcap_path: str, verbose: bool = False) -> AnalysisResult:
    result = AnalysisResult(pcap_path=pcap_path)
    result.c2_ip = _detect_c2_ip(pcap_path)
    result.c2_host, result.c2_port, result.c2_path = _get_ws_info(pcap_path)

    frames = extract_ws_frames(pcap_path, verbose=verbose)
    if not frames:
        return result

    last_beacon: Optional[BeaconInfo] = None
    server_payload_buf: List[bytes] = []    # accumulate multi-chunk deliveries
    server_payload_start: Optional[Tuple[int, float]] = None

    for frame in frames:
        # Skip pure heartbeats (12 bytes, no payload)
        if not frame.payload and frame.orig_size == 0:
            result.events.append(C2Event(
                frame_num=frame.frame_num,
                timestamp=frame.timestamp,
                stream=frame.stream,
                event_type="HEARTBEAT",
                direction=frame.direction,
                orig_size=frame.orig_size,
                note="keepalive",
            ))
            continue

        # For non-trivial frames: decrypt + classify
        if not frame.payload:
            continue

        event_type, cipher = _classify(frame, last_beacon)

        if event_type == "UNKNOWN":
            result.decode_errors += 1
            result.events.append(C2Event(
                frame_num=frame.frame_num,
                timestamp=frame.timestamp,
                stream=frame.stream,
                event_type="UNKNOWN",
                direction=frame.direction,
                orig_size=frame.orig_size,
                cipher_used=cipher,
                note=cipher,  # contains "S2C cmd_id=0x..." or "decrypt failed ..."
            ))
            continue

        # S2C raw commands don't need a second decrypt pass; they're already classified.
        # C2S frames and SERVER_PAYLOAD need full decrypt for content extraction.
        is_raw_srv_cmd = (frame.direction == "S2C"
                          and event_type not in ("SERVER_PAYLOAD",)
                          and cipher == "raw_command")
        if is_raw_srv_cmd:
            plaintext, cipher_used = None, "raw_command"
        else:
            plaintext, cipher_used = decrypt_payload(frame.payload)

        ev = C2Event(
            frame_num=frame.frame_num,
            timestamp=frame.timestamp,
            stream=frame.stream,
            event_type=event_type,
            direction=frame.direction,
            orig_size=frame.orig_size,
            plaintext=plaintext,
            cipher_used=cipher_used,
        )

        # Annotate raw server commands with payload size
        if is_raw_srv_cmd:
            ev.note = f"cmd_id=0x{frame.session_id:04x}  {len(frame.payload)}B payload"

        if event_type == "REGISTER" and plaintext:
            result.victim = _parse_victim_info(plaintext)
            ev.note = (f"{result.victim.hostname} | {result.victim.ip_address} | "
                       f"{result.victim.os_name()} | {result.victim.timestamp}")

        elif event_type == "AUTH_BEACON" and plaintext:
            new_beacon = _parse_beacon(plaintext)
            # Mini beacons (40B, no palette block) produce palette=[0x00].
            # Preserve the prior full beacon's palette so HiDPI screenshots render correctly.
            if last_beacon is not None and len(new_beacon.palette) <= 1:
                new_beacon.palette = last_beacon.palette
            last_beacon = new_beacon
            ev.note = (f"{last_beacon.screen_width}x{last_beacon.screen_height} "
                       f"screen, next_exfil={last_beacon.next_exfil_size:,}B")

        elif event_type in ("SCREENSHOT", "SCREENSHOT_HIDPI") and plaintext and last_beacon:
            if event_type == "SCREENSHOT_HIDPI":
                w = last_beacon.screen_width * 2
                h = last_beacon.screen_height * 2
            else:
                w = last_beacon.screen_width
                h = last_beacon.screen_height
            png_bytes = render_screenshot(plaintext, last_beacon.palette, w, h)
            if png_bytes:
                result.screenshots.append(
                    (frame.frame_num, frame.timestamp, png_bytes, last_beacon, w, h)
                )
                tag = " HiDPI/4K" if event_type == "SCREENSHOT_HIDPI" else ""
                ev.note = (f"{w}x{h}{tag} @ 4bpp → {len(png_bytes)//1024}KB PNG")
            else:
                ev.note = "render failed (PIL unavailable?)"

        elif event_type == "SCREEN_STREAM":
            # Tile-update frames; count but don't store individually to keep memory lean.
            result.screen_stream_frames += 1
            ev.note = f"{frame.orig_size}B tile"

        elif event_type == "FILE_LISTING" and plaintext:
            files = _parse_file_listing(plaintext)
            result.file_listings.append(
                (frame.frame_num, frame.timestamp, files)
            )
            ev.note = f"{len(files)} file names"

        elif event_type == "SERVER_PAYLOAD" and plaintext:
            # Accumulate chunks into one logical delivery
            if server_payload_start is None:
                server_payload_start = (frame.frame_num, frame.timestamp)
            server_payload_buf.append(plaintext)
            ev.note = f"chunk {len(server_payload_buf)}, {len(plaintext):,}B"
            # Flush when we detect a gap (next frame is not another server payload)
            # This is handled after the loop below
            result.server_payloads.append(
                (frame.frame_num, frame.timestamp, plaintext)
            )

        result.events.append(ev)

    return result


# ── Summary output ────────────────────────────────────────────────────────────

def print_summary(result: AnalysisResult) -> None:
    hr = "=" * 70

    print(hr)
    print("  Golden Gh0st RAT (APT-Q-27) PCAP Analysis Report")
    print(f"  Source: {result.pcap_path}")
    print(hr)

    print("\n[C2 Infrastructure]")
    print(f"  Host  : {result.c2_host or '(not detected)'}")
    print(f"  IP    : {result.c2_ip or '(not detected)'}")
    print(f"  Port  : {result.c2_port + '/tcp' if result.c2_port else '(not detected)'}")
    print(f"  Path  : {result.c2_path or '(not detected)'}")

    print("\n[Victim Fingerprint]")
    if result.victim:
        v = result.victim
        print(f"  OS        : {v.os_name()}")
        print(f"  Hostname  : {v.hostname or '(not recovered)'}")
        print(f"  IP        : {v.ip_address or '(not recovered)'}")
        print(f"  MAC       : {v.mac_address or '(not recovered)'}")
        print(f"  Infected  : {v.timestamp or '(not recovered)'} UTC")
    else:
        print("  (registration frame not found or decryption failed)")

    print("\n[C2 Operations Timeline]")
    prev_type = None
    repeat_count = 0
    for ev in result.events:
        if ev.event_type == "HEARTBEAT":
            continue
        ts = f"{ev.timestamp:8.1f}s"
        arrow = "→ C2" if ev.direction == "C2S" else "← C2"
        label = f"{ev.event_type:<16}"
        note = ev.note[:70] if ev.note else ""

        # Collapse repeated identical event types; suppress SCREEN_STREAM from timeline
        # (they are counted separately and would dominate/obscure the timeline)
        if ev.event_type == "SCREEN_STREAM":
            continue

        cur_key = (ev.event_type, ev.direction, ev.stream)
        if cur_key == prev_type:
            repeat_count += 1
            continue
        else:
            if repeat_count:
                print(f"           ... ({repeat_count} more {prev_type[0]})")
            repeat_count = 0
            prev_type = cur_key

        print(f"  F{ev.frame_num:<5} {ts} {arrow} {label} {note}")

    if repeat_count:
        print(f"         ... ({repeat_count} more {prev_type[0]})")

    print(f"\n  Total WebSocket events : {len(result.events)}")
    print(f"  Screenshots captured   : {len(result.screenshots)}")
    print(f"  Screen stream frames   : {result.screen_stream_frames}")
    print(f"  File listings          : {len(result.file_listings)}")
    print(f"  Server payload chunks  : {len(result.server_payloads)}")
    print(f"  Decode errors          : {result.decode_errors}")

    if result.file_listings:
        print("\n[Victim Desktop / Recent Files]")
        for listing_idx, (frame_num, ts, files) in enumerate(result.file_listings):
            print(f"  Listing #{listing_idx+1} (F{frame_num}, t={ts:.1f}s) — {len(files)} files:")
            for fname in sorted(files):
                print(f"    {fname}")

    print("\n[Screenshots]")
    if result.screenshots:
        for i, (fn, ts, png_bytes, beacon, rw, rh) in enumerate(result.screenshots):
            hidpi = " HiDPI/4K" if (rw > beacon.screen_width or rh > beacon.screen_height) else ""
            print(f"  Screenshot #{i+1}: F{fn} t={ts:.1f}s | "
                  f"{rw}x{rh}{hidpi} 4bpp | "
                  f"compressed→{len(png_bytes)//1024}KB PNG")
    else:
        print("  (none captured or render failed)")

    print()


# ── Extract mode ──────────────────────────────────────────────────────────────

def _format_fingerprint_text(victim: VictimInfo, plaintext: bytes) -> str:
    """Format the 516-byte fingerprint as a human-readable text report."""
    lines = []
    lines.append("Golden Gh0st RAT (APT-Q-27) — Victim Fingerprint")
    lines.append("=" * 50)

    lines.append("\n[Operating System]")
    lines.append(f"  Name         : {victim.os_name()}")
    lines.append(f"  Version      : {victim.os_major}.{victim.os_minor}")
    lines.append(f"  Build        : {victim.os_build}")
    if len(plaintext) >= 284:
        ptype = plaintext[282]
        suite = struct.unpack_from("<H", plaintext, 280)[0]
        product_types = {1: "Workstation", 2: "Domain Controller", 3: "Server"}
        lines.append(f"  Product type : {product_types.get(ptype, f'Unknown ({ptype})')}")
        lines.append(f"  Suite mask   : 0x{suite:04x}")

    lines.append("\n[Network Identity]")
    lines.append(f"  Hostname     : {victim.hostname or '(not recovered)'}")
    lines.append(f"  Primary IP   : {victim.ip_address or '(not recovered)'}")
    lines.append(f"  MAC address  : {victim.mac_address or '(not recovered)'}")

    # Collect all plausible private IPs from the plaintext
    all_ips = []
    for i in range(0, len(plaintext) - 3):
        b = plaintext[i:i+4]
        if b[0] in (10, 172, 192) or (b[0] == 169 and b[1] == 254):
            ip = f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"
            if b[2] != 0 and b[3] not in (0, 255) and ip not in all_ips:
                all_ips.append(ip)
    secondary = [ip for ip in all_ips if ip != victim.ip_address]
    if secondary:
        lines.append(f"  Other IPs    : {', '.join(secondary)}")

    lines.append("\n[Infection]")
    lines.append(f"  Timestamp    : {victim.timestamp or '(not recovered)'} UTC")

    # Additional fields appended by Golden Gh0st RAT after OSVERSIONINFOEX
    lines.append("\n[Raw Fingerprint Fields (post-OSVERSIONINFOEX)]")
    prefix_bytes = plaintext[284:286].hex() if len(plaintext) >= 286 else "?"
    lines.append(f"  Prefix bytes : 0x{prefix_bytes}")

    ts_end = plaintext.find(b"\x00", 286)
    if ts_end > 286:
        off = ts_end + 1
        dwords = []
        for i in range(off, min(len(plaintext), off + 120), 4):
            if i + 4 <= len(plaintext):
                v = struct.unpack_from("<I", plaintext, i)[0]
                if v != 0:
                    dwords.append(f"  offset {i:4d} : 0x{v:08x}  ({v})")
        if dwords:
            lines.append("  Non-zero DWORDs after timestamp:")
            lines.extend(dwords)

    lines.append("\n[Raw Bytes]")
    for i in range(0, len(plaintext), 16):
        row = plaintext[i:i+16]
        hex_s = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row)
        lines.append(f"  {i:04x}: {hex_s:<48}  |{asc}|")

    return "\n".join(lines) + "\n"


def extract_artifacts(result: AnalysisResult, out_dir: str) -> None:
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)

    # Screenshots
    for i, (frame_num, ts, png_bytes, beacon, rw, rh) in enumerate(result.screenshots):
        hidpi_tag = "_hidpi" if (rw > beacon.screen_width or rh > beacon.screen_height) else ""
        fname = base / f"screenshot_{i+1:02d}_F{frame_num}_{ts:.0f}s{hidpi_tag}.png"
        fname.write_bytes(png_bytes)
        print(f"[+] Screenshot saved: {fname}  ({rw}x{rh})")

    # File listings
    for i, (frame_num, ts, files) in enumerate(result.file_listings):
        fname = base / f"file_listing_{i+1:02d}_F{frame_num}_{ts:.0f}s.txt"
        fname.write_text("\n".join(sorted(files)) + "\n")
        print(f"[+] File listing saved: {fname}  ({len(files)} entries)")

    # Server payloads — save raw chunks, then assemble + cipher2-decrypt + UPX-unpack
    chunk_bytes = []
    for i, (frame_num, ts, payload_bytes) in enumerate(result.server_payloads):
        fname = base / f"server_payload_{i+1:02d}_F{frame_num}_{ts:.0f}s.bin"
        fname.write_bytes(payload_bytes)
        print(f"[+] Server payload chunk saved: {fname}  ({len(payload_bytes):,}B)")
        chunk_bytes.append(payload_bytes)

    if chunk_bytes:
        assembled = _assemble_plugin_payload(chunk_bytes)
        if assembled:
            enc_path = base / "plugin_assembled_encrypted.bin"
            enc_path.write_bytes(assembled)
            print(f"[+] Plugin assembled (cipher2-encrypted): {enc_path}  ({len(assembled):,}B)")

            decrypted = _cipher2_at_rest_decrypt(assembled, MODULE_KEY)
            if decrypted[:2] == b"MZ":
                dec_path = base / "plugin_assembled_decrypted.bin"
                dec_path.write_bytes(decrypted)
                print(f"[+] Plugin cipher2-decrypted (MZ OK):   {dec_path}  ({len(decrypted):,}B)")

                # Attempt UPX unpack
                upx_path = base / "plugin32.dll"
                import shutil, tempfile
                with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as tmp:
                    tmp_name = tmp.name
                    tmp.write(decrypted)
                try:
                    upx_result = subprocess.run(
                        ["upx", "-d", "-o", str(upx_path), tmp_name],
                        capture_output=True, text=True, timeout=60
                    )
                    if upx_result.returncode == 0 and upx_path.exists():
                        print(f"[+] Plugin UPX-unpacked:             {upx_path}  ({upx_path.stat().st_size:,}B)")
                    else:
                        # Not UPX-packed — copy decrypted as-is
                        shutil.copy(dec_path, upx_path)
                        print(f"[!] UPX unpack skipped (not packed); raw PE saved as: {upx_path}")
                except FileNotFoundError:
                    shutil.copy(dec_path, upx_path)
                    print(f"[!] upx not found; raw decrypted PE saved as: {upx_path}")
                finally:
                    os.unlink(tmp_name)
            else:
                print(f"[!] cipher2 decrypt did not produce MZ header — check MODULE_KEY")
                raw_path = base / "plugin_assembled_decrypt_attempt.bin"
                raw_path.write_bytes(decrypted)
                print(f"    Raw attempt saved to: {raw_path}")

    # Victim fingerprint — human-readable text
    if result.victim:
        for ev in result.events:
            if ev.event_type == "REGISTER" and ev.plaintext:
                text = _format_fingerprint_text(result.victim, ev.plaintext)
                fname = base / "victim_fingerprint.txt"
                fname.write_text(text)
                print(f"[+] Victim fingerprint saved: {fname}")
                break

    print(f"\n[+] All artifacts saved to: {out_dir}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Golden Gh0st RAT (APT-Q-27) PCAP Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("pcap_pos", nargs="?", metavar="PCAP", help="Path to .pcap file (positional)")
    parser.add_argument("--pcap", default=None, help="Path to .pcap file (named flag)")
    parser.add_argument(
        "--mode",
        choices=["summary", "extract", "both"],
        default="summary",
        help="summary: print report | extract: save files | both: do both (default: summary)",
    )
    parser.add_argument(
        "--out-dir",
        default="./gg_extracted",
        help="Output directory for extract mode (default: ./gg_extracted)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    pcap_path = args.pcap or args.pcap_pos

    if not pcap_path:
        parser.print_help()
        sys.exit(0)

    if not os.path.isfile(pcap_path):
        print(f"ERROR: PCAP file not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    result = analyze(pcap_path, verbose=args.verbose)

    if args.mode in ("summary", "both"):
        print_summary(result)

    if args.mode in ("extract", "both"):
        extract_artifacts(result, args.out_dir)


if __name__ == "__main__":
    main()
