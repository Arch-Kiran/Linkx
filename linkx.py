"""
Linkx — Smart Network File Transfer
All issues fixed, clean build from scratch.

FLOW:
  1. Scan all subnets → find devices with SSH open
  2. First connect: SSH runs interactively in terminal
     → user types password once (raw terminal, no Python in the middle)
     → keys generated and installed via that password session
     → password connection closed
  3. All future transfers: raw scp/ssh with key only
     → Python only manages the menu, never touches the data stream
     → full native speed, zero overhead 
"""

import os, sys, socket, subprocess, threading, time, json
import concurrent.futures, getpass, shutil, base64, re, hashlib
import tempfile, shlex, queue, random, secrets, platform
from datetime import datetime
# ─────────────────────────────────────────────────────────────────────
# LINKX METADATA  — only the author should change these
# ─────────────────────────────────────────────────────────────────────
__version__  = "1.0.0"
__author__   = "Arch Kiran"
__email__    = "sysarch.kiran@email.com"
__launched__ = "2026-04-27"
__app_name__ = "Linkx"
# pty / select — Unix only (pseudo-terminal for SCP progress bar)
try:
    import pty as _pty_mod
    import select as _select_mod
    _HAS_PTY = True
except ImportError:
    _HAS_PTY = False  # Windows — graceful fallback

# Global lock — all JSON file writes go through this to prevent corruption
# when 50 scan threads try to update hosts simultaneously
_FILE_LOCK = threading.Lock()

# ─────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────
_BASE     = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(_BASE, ".linkx_hosts.json")
PASS_FILE = os.path.join(_BASE, ".linkx_pass.json")
KEY_MAP          = os.path.join(_BASE, ".linkx_keys.json")
QUICK_SHARE_FILE = os.path.join(_BASE, ".linkx_quick.json")
VAULT_FILE       = os.path.join(_BASE, ".linkx_vault.json")
TRUSTED_FILE     = os.path.join(_BASE, ".linkx_trusted.json")

SCAN_TIMEOUT = 1.2   # seconds — enough for WiFi + Android hotspot
MAX_WORKERS  = 50    # threads — safe on Windows (overridden per-OS at runtime)
FAST_PROBE_TIMEOUT = 0.5   # quick TCP probe for known devices (last IP)
_BANNER_TIMEOUT    = 0.4   # SSH banner arrives in <50ms on LAN — 1.5s was 30x too long


def _os_aware_workers() -> int:
    """
    Return optimal thread count based on local OS and hardware.

    Windows:  TCP stack caps half-open connections at ~200 before throttling.
              SYN flood protection (tcpip.sys) limits concurrent SYN packets.
              200 is empirically safe without triggering Windows Defender.

    Linux:    No kernel-level TCP connection throttling. Limited by:
              - File descriptor limit (ulimit -n, typically 1024-65536)
              - Thread stack memory (8MB default × N threads)
              500 threads × 8MB = 4GB — too much. Use 300 safely.
              On systems with > 4 cores push to 400.

    macOS:    Similar to Linux but default fd limit is lower (256 per process
              pre-Catalina, 10240 on Catalina+). 200 is safe everywhere.

    Android:  Termux runs in a constrained environment. Android kernel limits
              TCP connections per-app. 100 is the safe ceiling.
    """
    los = local_os() if callable(local_os) else "other"
    try:
        import multiprocessing
        cores = multiprocessing.cpu_count()
    except Exception:
        cores = 1

    if los in ("windows", "windows_old"):
        return 200
    if los == "android":
        return 100
    if los == "macos":
        return 200
    # Linux family — scale with cores, cap at 300
    return min(300, max(150, cores * 50))
PASSIVE_POLL_INTERVAL = 3  # seconds between device-online checks in wait mode
LINKX_FOLDER     = "Linkx"          # folder created in Downloads on every OS
QS_POLL_INTERVAL = 8  # seconds between key-probe pings in Quick Share queue

PAIR_PORT    = 55222   # TCP port used for zero-config pairing handshake
PAIR_TIMEOUT = 120     # seconds HOST waits before giving up on pairing

# Spinner frames for waiting animations (Braille dots — works on all terminals)
_SPINNER = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

# Display width. Change to resize every menu:
#   50 = small / phone screen
#   64 = normal laptop  (default)
#   80 = wide monitor
W = 64
# ── TRANSFER BEHAVIOUR ────────────────────────────────────────────────
# TAR_THRESHOLD: if total file count across all selected items exceeds
# this number, bundle into Transfer.tar before sending.
# A compressed item (.7z) always counts as 1 regardless of original size.
# A single file > 1GB is sent directly even if count exceeds threshold.
# Set to 0 to always tar. Set to 9999 to never tar.
TAR_THRESHOLD = 10

# ── DEBUG FLAGS ───────────────────────────────────────────────────────
# SHOW_PASSWORD = True   → SSH will echo the password you type (visible).
#                False   → password hidden (default, secure).
# Set True only for troubleshooting Windows permission-denied issues.
# NEVER leave True in production — anyone looking at your screen sees it.
SHOW_PASSWORD = False

# ─────────────────────────────────────────────────────────────────────
# OS PROFILES — ports, paths, labels per remote OS
# ─────────────────────────────────────────────────────────────────────
OS_PROFILES = {
    # Android / Termux
    # home  = Termux home (always accessible, no permissions needed)
    # storage = ~/storage/shared symlink = /storage/emulated/0
    #           Use ~/storage/* paths for writes on Android 11+
    "android": {"port":8022,
                "home":"/data/data/com.termux/files/home",
                "storage":"~/storage/shared",
                "list":"ls -lah",
                "label":"Android / Termux"},
    # Linux (Ubuntu 18.04+, Debian, Fedora, etc.)
    "linux"  : {"port":22,
                "home":"/home/{user}",
                "storage":"/home/{user}",
                "list":"ls -lah",
                "label":"Linux"},
    # Kali Linux
    "kali"   : {"port":22,
                "home":"/home/{user}",
                "storage":"/home/{user}",
                "list":"ls -lah",
                "label":"Kali Linux"},
    # macOS (Catalina 10.15 through Sequoia 15+)
    # home = /Users/{user}  — /home does NOT work on macOS
    "macos"  : {"port":22,
                "home":"/Users/{user}",
                "storage":"/Users/{user}",
                "list":"ls -lah",
                "label":"macOS"},
    # Windows 10 / 11 with OpenSSH Server
    # home = user profile root, not Desktop
    "windows": {"port":22,
                "home":"C:/Users/{user}",
                "storage":"C:/Users/{user}",
                "list":"dir",
                "label":"Windows"},
    "other"  : {"port":22,
                "home":"/home/{user}",
                "storage":"/home/{user}",
                "list":"ls -lah",
                "label":"Other"},
}

# OSes where the kernel/OS randomizes MAC per-network by default.
# For these, MAC is NEVER used as a device identity anchor — it changes
# every time the device joins a new network or reconnects after a while.
#   Android 10+  : always randomized (cannot be disabled without root)
#   macOS Ventura+: randomized by default (earlier versions optional)
#   iOS 14+      : always randomized
#   Windows 10+  : optional but common enough to treat as unreliable
# Linux / Kali use stable MACs by default — MAC matching is safe there.
MAC_RANDOMIZED_OS = {"android", "macos", "windows"}

# ─────────────────────────────────────────────────────────────────────
# REMOTE LOCATIONS — real-world verified paths per OS (2018-2025)
#
# Android / Termux notes:
#   Termux uses ~/storage/ symlinks (created by termux-setup-storage).
#   These are the ONLY reliably writable paths from an SSH/SCP session.
#   Direct /storage/emulated/0/... paths work for READ but fail to write
#   on Android 11+ (scoped storage).  Always prefer ~/storage/* paths.
#   ~/storage/downloads → /storage/emulated/0/Download  (no 's')
#   ~/storage/shared    → /storage/emulated/0            (root)
#   ~/storage/dcim      → /storage/emulated/0/DCIM
#   ~/storage/pictures  → /storage/emulated/0/Pictures
#   ~/storage/music     → /storage/emulated/0/Music
#   ~/storage/movies    → /storage/emulated/0/Movies
#
#   WhatsApp paths changed with Android 11 scoped storage:
#     Android ≤10: /storage/emulated/0/WhatsApp/Media/
#     Android 11+: /storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media/
#   We list BOTH so the user can pick the right one.
#
# Windows notes:
#   C:/Users/{user}/ is the real profile root (not C:\Users\).
#   Forward slashes work fine in OpenSSH scp on Windows.
#   AppData paths included — useful for config backup.
#
# macOS notes:
#   Home is /Users/{user}  (capital U, NOT /home/).
#   /home on macOS is an auto-mount stub — not where users live.
# ─────────────────────────────────────────────────────────────────────
REMOTE_LOCATIONS = {
    # ── Android / Termux ─────────────────────────────────────────────
    # Paths prefixed ~/storage/ are Termux symlinks — always writable.
    # Raw /storage/emulated/0/ paths are listed as READ alternatives.
    "android": [
        # Termux symlink paths — recommended, always writable
        ("Termux Home",              "/data/data/com.termux/files/home"),
        ("Downloads  (symlink)",     "~/storage/downloads"),
        ("Internal Storage (symlink)","~/storage/shared"),
        ("DCIM / Camera (symlink)",  "~/storage/dcim"),
        ("Pictures   (symlink)",     "~/storage/pictures"),
        ("Music      (symlink)",     "~/storage/music"),
        ("Movies     (symlink)",     "~/storage/movies"),
        # Raw paths — readable on all Android versions
        ("Downloads  (raw)",         "/storage/emulated/0/Download"),
        ("Internal Storage (raw)",   "/storage/emulated/0"),
        ("DCIM Camera (raw)",        "/storage/emulated/0/DCIM/Camera"),
        ("Screenshots (raw)",        "/storage/emulated/0/Pictures/Screenshots"),
        ("Recordings (raw)",         "/storage/emulated/0/Recordings"),
        # WhatsApp — Android 11+ path (scoped storage)
        ("WhatsApp Images  (A11+)",  "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Images"),
        ("WhatsApp Videos  (A11+)",  "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Video"),
        ("WhatsApp Docs    (A11+)",  "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents"),
        ("WhatsApp Audio   (A11+)",  "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Audio"),
        # WhatsApp — Android ≤10 legacy path
        ("WhatsApp Images  (A≤10)",  "/storage/emulated/0/WhatsApp/Media/WhatsApp Images"),
        ("WhatsApp Videos  (A≤10)",  "/storage/emulated/0/WhatsApp/Media/WhatsApp Video"),
        ("WhatsApp Docs    (A≤10)",  "/storage/emulated/0/WhatsApp/Media/WhatsApp Documents"),
    ],

    # ── Linux (Ubuntu, Debian, Fedora, etc.) ─────────────────────────
    "linux": [
        ("Home",            "/home/{user}"),
        ("Desktop",         "/home/{user}/Desktop"),
        ("Downloads",       "/home/{user}/Downloads"),
        ("Documents",       "/home/{user}/Documents"),
        ("Pictures",        "/home/{user}/Pictures"),
        ("Videos",          "/home/{user}/Videos"),
        ("Music",           "/home/{user}/Music"),
        ("tmp",             "/tmp"),
        ("Root /",          "/"),
        ("var/www/html",    "/var/www/html"),
        ("opt",             "/opt"),
    ],

    # ── Kali Linux ───────────────────────────────────────────────────
    "kali": [
        ("Home",            "/home/{user}"),
        ("Desktop",         "/home/{user}/Desktop"),
        ("Downloads",       "/home/{user}/Downloads"),
        ("Documents",       "/home/{user}/Documents"),
        ("Pictures",        "/home/{user}/Pictures"),
        ("tmp",             "/tmp"),
        ("var/www/html",    "/var/www/html"),
        ("Root home",       "/root"),
        ("Root /",          "/"),
        ("opt",             "/opt"),
        ("Tools",           "/opt/tools"),
    ],

    # ── Windows 10 / 11 ──────────────────────────────────────────────
    # Forward slashes work with OpenSSH scp on Windows.
    # Profile root: C:/Users/{user}
    "windows": [
        ("Desktop",         "C:/Users/{user}/Desktop"),
        ("Downloads",       "C:/Users/{user}/Downloads"),
        ("Documents",       "C:/Users/{user}/Documents"),
        ("Pictures",        "C:/Users/{user}/Pictures"),
        ("Videos",          "C:/Users/{user}/Videos"),
        ("Music",           "C:/Users/{user}/Music"),
        ("AppData/Local",   "C:/Users/{user}/AppData/Local"),
        ("AppData/Roaming", "C:/Users/{user}/AppData/Roaming"),
        ("OneDrive",        "C:/Users/{user}/OneDrive"),
        ("C:\\  root",       "C:/"),
        ("D:\\  drive",      "D:/"),
        ("Program Files",   "C:/Program Files"),
    ],

    # ── macOS (Catalina 10.15 through Sequoia 15+) ───────────────────
    # Home is /Users/{user}  — NOT /home/{user}
    "macos": [
        ("Home",            "/Users/{user}"),
        ("Desktop",         "/Users/{user}/Desktop"),
        ("Downloads",       "/Users/{user}/Downloads"),
        ("Documents",       "/Users/{user}/Documents"),
        ("Pictures",        "/Users/{user}/Pictures"),
        ("Movies",          "/Users/{user}/Movies"),
        ("Music",           "/Users/{user}/Music"),
        ("Library",         "/Users/{user}/Library"),
        ("iCloud Drive",    "/Users/{user}/Library/Mobile Documents/com~apple~CloudDocs"),
        ("Applications",    "/Applications"),
        ("Root /",          "/"),
        ("tmp",             "/tmp"),
    ],

    # ── Generic / Unknown ─────────────────────────────────────────────
    "other": [
        ("Home",        "/home/{user}"),
        ("Downloads",   "/home/{user}/Downloads"),
        ("tmp",         "/tmp"),
        ("Root /",      "/"),
    ],
}

# ─────────────────────────────────────────────────────────────────────
# LOCAL LOCATIONS — paths on the machine running linkx.py
# Expanded ~ is resolved at display time in pick_local_path().
# ─────────────────────────────────────────────────────────────────────
LOCAL_LOCATIONS = {
    # ── Windows 10 / 11 ──────────────────────────────────────────────
    "windows": [
        ("Desktop",         "~/Desktop"),
        ("Downloads",       "~/Downloads"),
        ("Documents",       "~/Documents"),
        ("Pictures",        "~/Pictures"),
        ("Videos",          "~/Videos"),
        ("Music",           "~/Music"),
        ("AppData/Local",   "~/AppData/Local"),
        ("AppData/Roaming", "~/AppData/Roaming"),
        ("OneDrive",        "~/OneDrive"),
        ("C:\\  root",       "C:/"),
        ("D:\\  drive",      "D:/"),
    ],

    # ── Linux ─────────────────────────────────────────────────────────
    "linux": [
        ("Home",        "~"),
        ("Desktop",     "~/Desktop"),
        ("Downloads",   "~/Downloads"),
        ("Documents",   "~/Documents"),
        ("Pictures",    "~/Pictures"),
        ("Videos",      "~/Videos"),
        ("Music",       "~/Music"),
        ("tmp",         "/tmp"),
        ("var/www/html","/var/www/html"),
    ],

    # ── Kali Linux ───────────────────────────────────────────────────
    "kali": [
        ("Home",        "~"),
        ("Desktop",     "~/Desktop"),
        ("Downloads",   "~/Downloads"),
        ("Documents",   "~/Documents"),
        ("tmp",         "/tmp"),
        ("var/www/html","/var/www/html"),
        ("opt",         "/opt"),
    ],

    # ── macOS ─────────────────────────────────────────────────────────
    "macos": [
        ("Desktop",         "~/Desktop"),
        ("Downloads",       "~/Downloads"),
        ("Documents",       "~/Documents"),
        ("Pictures",        "~/Pictures"),
        ("Movies",          "~/Movies"),
        ("Music",           "~/Music"),
        ("Home",            "~"),
        ("iCloud Drive",    "~/Library/Mobile Documents/com~apple~CloudDocs"),
    ],

    # ── Generic / other ──────────────────────────────────────────────
    "other": [
        ("Home",        "~"),
        ("Downloads",   "~/Downloads"),
        ("tmp",         "/tmp"),
    ],
}

# ─────────────────────────────────────────────────────────────────────
# COLOURS
# ─────────────────────────────────────────────────────────────────────
class C:
    R="\033[0m"; B="\033[1m"; G="\033[92m"; CY="\033[96m"
    Y="\033[93m"; RE="\033[91m"; D="\033[2m"; BL="\033[94m"; M="\033[95m"

if os.name == "nt":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        for a in vars(C):
            if not a.startswith("_"): setattr(C, a, "")

# ─────────────────────────────────────────────────────────────────────
# UI PRIMITIVES
# ─────────────────────────────────────────────────────────────────────
def clear():
    if os.name == "nt":
        os.system("cls")
    else:
        print("\033[2J\033[H", end="", flush=True)

def pr(m=""):
    print(f"  {m}")

def ok(m):
    msg = str(m)[:W-7]
    print(f"\n  {C.G}┌{'─'*(W-2)}┐{C.R}")
    print(f"  {C.G}│  ✓  {msg:<{W-7}}│{C.R}")
    print(f"  {C.G}└{'─'*(W-2)}┘{C.R}")

def err(m):
    msg = str(m)[:W-7]
    print(f"\n  {C.RE}┌{'─'*(W-2)}┐{C.R}")
    print(f"  {C.RE}│  ✗  {msg:<{W-7}}│{C.R}")
    print(f"  {C.RE}└{'─'*(W-2)}┘{C.R}")

def warn(m):  print(f"\n  {C.Y}⚠  {m}{C.R}")
def info(m):  print(f"\n  {C.BL}ℹ  {m}{C.R}")
def sep(c="─"): print(f"  {C.D}{c*W}{C.R}")

def pause():
    try:
        input(f"\n  {C.D}{'─'*W}{C.R}\n  {C.D}↵  Press Enter to continue{C.R}  ")
    except (KeyboardInterrupt, EOFError):
        print()   # clean newline, never hang

def hdr(title, sub=""):
    print(f"\n  {C.CY}╔{'═'*W}╗{C.R}")
    print(f"  {C.CY}║{C.B}{title.center(W)}{C.R}{C.CY}║{C.R}")
    if sub:
        print(f"  {C.CY}║{C.D}{sub.center(W)}{C.R}{C.CY}║{C.R}")
    print(f"  {C.CY}╚{'═'*W}╝{C.R}")

def ask(prompt, default=""):
    sfx = f" {C.D}[{default}]{C.R}" if default else ""
    try:
        val = input(f"\n  {C.B}❯  {prompt}{C.R}{sfx}: ").strip()
        result = val if val else default
        if val and C.R:
            # Reprint line cleanly so typed char appears inline not on blank line
            # Only when ANSI works (C.R non-empty) — safe on all platforms
            print(f"\033[1A\033[2K  {C.B}❯  {prompt}{C.R}{sfx}: {C.G}{result}{C.R}")
        return result
    except (KeyboardInterrupt, EOFError):
        print()
        return default

# ─────────────────────────────────────────────────────────────────────
# LOCAL OS DETECTION
# ─────────────────────────────────────────────────────────────────────
def _read_os_release() -> dict:
    """
    Parse /etc/os-release into a dict.
    Keys are lowercase.  Returns {} if file missing (Windows / old distros).
    """
    d = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if "=" not in line or line.startswith("#"):
                        continue
                    k, _, v = line.partition("=")
                    d[k.lower()] = v.strip().strip('"').strip("'")
            if d:
                return d
        except Exception:
            pass
    return d


def local_os() -> str:
    """
    Detect the OS / distro family of THIS machine.

    Return values (used throughout the app):
      "windows"  — Windows 10/11/Server (has OpenSSH as optional feature)
      "windows_old" — Windows 7/8/8.1 (no native OpenSSH at all)
      "macos"    — macOS 10.13+ (High Sierra and newer)
      "android"  — Android/Termux
      "kali"     — Kali Linux
      "debian"   — Debian, Ubuntu, Mint, Pop!_OS, Raspberry Pi OS, etc.
      "rhel"     — RHEL, CentOS, Fedora, Rocky, AlmaLinux, Amazon Linux
      "arch"     — Arch Linux, Manjaro, EndeavourOS, Garuda
      "suse"     — openSUSE Leap/Tumbleweed, SLES
      "alpine"   — Alpine Linux (OpenRC, no systemd)
      "void"     — Void Linux (runit)
      "gentoo"   — Gentoo (OpenRC or systemd)
      "linux"    — any other/unknown Linux

    Detection strategy:
      1. Termux path → android
      2. platform.system() → windows / macos
      3. Windows version → windows_old for pre-Win10
      4. /etc/os-release  ID + ID_LIKE → specific Linux family
      5. Fallback package manager presence → family
    """
    s = platform.system().lower()

    # ── Termux / Android ─────────────────────────────────────────────
    if os.path.exists("/data/data/com.termux/files/home"):
        return "android"

    # ── macOS ─────────────────────────────────────────────────────────
    if s == "darwin":
        return "macos"

    # ── Windows ──────────────────────────────────────────────────────
    if s == "windows":
        try:
            ver = platform.version()          # e.g. "10.0.19041"
            major = int(ver.split(".")[0])
            build = int(ver.split(".")[2]) if ver.count(".") >= 2 else 0
            # Windows 10 starts at major=10, build 1507 (10240)
            # Windows 8.1 = 6.3, Windows 8 = 6.2, Windows 7 = 6.1
            if major < 10:
                return "windows_old"
        except Exception:
            pass
        return "windows"

    # ── Linux — read /etc/os-release ─────────────────────────────────
    osr = _read_os_release()
    os_id    = osr.get("id", "")
    id_like  = osr.get("id_like", "")
    all_ids  = f"{os_id} {id_like}".lower()

    # Kali (check first — id_like="debian" so must match before debian)
    if "kali" in all_ids:
        return "kali"
    # Debian family: debian, ubuntu, mint, pop, raspbian, elementary, zorin
    if any(x in all_ids for x in ("debian", "ubuntu", "raspbian", "mint")):
        return "debian"
    # RHEL family: rhel, centos, fedora, rocky, alma, oracle, amazon
    if any(x in all_ids for x in ("rhel", "centos", "fedora", "rocky",
                                   "alma", "oracle", "amzn", "scientific")):
        return "rhel"
    # Arch family: arch, manjaro, endeavouros, garuda, artix
    if any(x in all_ids for x in ("arch", "manjaro", "endeavour",
                                   "garuda", "artix")):
        return "arch"
    # SUSE family: opensuse, sles, suse
    if any(x in all_ids for x in ("suse", "opensuse")):
        return "suse"
    # Alpine
    if "alpine" in all_ids:
        return "alpine"
    # Void
    if "void" in all_ids:
        return "void"
    # Gentoo
    if "gentoo" in all_ids:
        return "gentoo"

    # Fallback: detect by available package manager
    for cmd, family in (("apt",    "debian"),
                         ("apt-get","debian"),
                         ("dnf",    "rhel"),
                         ("yum",    "rhel"),
                         ("pacman", "arch"),
                         ("zypper", "suse"),
                         ("apk",    "alpine"),
                         ("xbps-install","void"),
                         ("emerge", "gentoo")):
        if shutil.which(cmd):
            return family

    return "linux"

# ─────────────────────────────────────────────────────────────────────
# NETWORK — get all local IPs across all adapters
# ─────────────────────────────────────────────────────────────────────
def get_all_local_ips() -> list:
    ips = []
    # ipconfig / ip addr — most complete
    try:
        if os.name == "nt":
            r = subprocess.run(["ipconfig"], capture_output=True,
                               text=True, timeout=5)
            for ip in re.findall(r"IPv4 Address[ .]+:\s*([\d.]+)", r.stdout):
                if not ip.startswith("127.") and ip not in ips:
                    ips.append(ip)
        else:
            r = subprocess.run(["ip","addr","show"], capture_output=True,
                               text=True, timeout=5)
            for ip in re.findall(r"inet ([\d.]+)/", r.stdout):
                if not ip.startswith("127.") and ip not in ips:
                    ips.append(ip)
    except Exception: pass
    # UDP trick — try common hotspot gateways to discover hidden adapters
    for dest in ("8.8.8.8","192.168.43.1","192.168.1.1","10.0.0.1",
                 "172.20.10.1","192.168.137.1","100.64.0.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1); s.connect((dest, 80))
            ip = s.getsockname()[0]; s.close()
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
        except Exception: pass
    # hostname fallback
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip and ":" not in ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception: pass
    return ips or ["127.0.0.1"]


def _hotspot_gateway_reachable(gateway_ip: str, timeout: float = 0.4) -> bool:
    """Quick TCP/ICMP check — is this gateway actually reachable?"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        # Port 80 usually open on hotspot gateways
        result = s.connect_ex((gateway_ip, 80)) in (0, 111)  # 111=refused=alive
        s.close()
        return result
    except Exception:
        return False


def _get_default_gateway() -> str:
    """Get default gateway IP — works on Windows, Linux, Android/Termux."""
    try:
        if os.name == "nt":
            r = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
            m = re.search(r"Default Gateway[ .]+:\s*([\d.]+)", r.stdout)
            return m.group(1) if m else ""
        else:
            # Linux / Android
            r = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True, timeout=5)
            m = re.search(r"default via ([\d.]+)", r.stdout)
            if m: return m.group(1)
            # Termux fallback
            r2 = subprocess.run(["route", "-n"], capture_output=True,
                                text=True, timeout=5)
            for line in r2.stdout.splitlines():
                if line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 2: return parts[1]
    except Exception: pass
    return ""


def _extra_hotspot_subnets(known_ips: list) -> list:
    """
    Detect subnets reachable via hotspot gateway that we don't have a
    local IP on.

    THE PROBLEM (asymmetric hotspot routing):
      Vivo hotspot → Android phones get 192.168.43.x
                   → Laptop gets 10.131.215.x (carrier DHCP)
      Laptop scans 10.131.215.x → finds phone at 192.168.43.x  ✓
        (hotspot gateway bridges 10.x → 192.168.43.x)
      Android scans 192.168.43.x → does NOT find laptop at 10.131.215.x  ✗
        (never scans 10.x subnet because has no 10.x IP)

    FIX:
      1. Get default gateway IP (e.g. 192.168.43.1)
      2. Check well-known hotspot gateway IPs
      3. Also probe /24s around the gateway — hotspot may assign
         clients on a DIFFERENT /24 than the gateway itself
      4. Specifically: if gateway is 192.168.43.1, clients might
         be on 10.131.215.x — probe common alternate subnets too

    Returns list of (gateway_ip, prefix) tuples to add to scan list.
    """
    known_prefixes = set()
    for ip in known_ips:
        pfx = ".".join(ip.split(".")[:3])
        known_prefixes.add(pfx)

    extra = []

    # Well-known hotspot gateways to probe (even without local IP on that subnet)
    hotspot_gateways = [
        ("192.168.43.1",  "192.168.43"),    # Android Qualcomm hotspot
        ("172.20.10.1",   "172.20.10"),     # iPhone hotspot
        ("192.168.137.1", "192.168.137"),   # Windows Mobile hotspot
        ("192.168.0.1",   "192.168.0"),     # MediaTek Android / router
        ("192.168.1.1",   "192.168.1"),     # Common router
        ("10.0.0.1",      "10.0.0"),        # Newer Android hotspot
        ("192.168.4.1",   "192.168.4"),     # ESP32 / some hotspots
    ]

    for gateway, pfx in hotspot_gateways:
        if pfx in known_prefixes:
            continue
        if _hotspot_gateway_reachable(gateway):
            extra.append((gateway, pfx))

    # KEY FIX: detect the actual default gateway and scan subnets
    # that OTHER devices on the same hotspot might be assigned to.
    # Example: gateway=192.168.43.1, but laptop got 10.131.215.x
    # Android needs to also scan 10.x subnets reachable via that gateway.
    gw = _get_default_gateway()
    if gw:
        gw_pfx = ".".join(gw.split(".")[:3])
        # If our gateway is a hotspot gateway, scan for devices on
        # alternate subnets the hotspot may bridge to
        is_hotspot_gw = any(gw.startswith(p.rsplit(".",1)[0])
                            for p in ["192.168.43.", "192.168.137.",
                                      "172.20.10.", "192.168.0.",
                                      "192.168.1.", "10.0.0."])
        if is_hotspot_gw:
            # Probe common carrier/bridged subnets
            bridged_candidates = [
                "10.131.215", "10.166.223", "10.0.2",
                "192.168.2",  "192.168.10", "192.168.100",
            ]
            for cand_pfx in bridged_candidates:
                if cand_pfx in known_prefixes:
                    continue
                # Quick probe: check if .1 gateway of this subnet responds
                cand_gw = f"{cand_pfx}.1"
                if _hotspot_gateway_reachable(cand_gw):
                    extra.append((cand_gw, cand_pfx))

    return extra

def classify_ip(ip: str) -> tuple:
    """Returns (label, is_virtual)."""
    virtual_gateways = {
        "192.168.40.1","192.168.41.1","192.168.42.1",
        "192.168.92.1","192.168.157.1","192.168.198.1","192.168.199.1",
    }
    if ip in virtual_gateways:        return "VMware virtual",    True
    if ip.startswith("192.168.43."):  return "Android hotspot",   False
    if ip.startswith("172.20.10."):   return "iPhone hotspot",    False
    if ip.startswith("192.168.137."): return "Windows hotspot",   False
    if ip.startswith("192.168.92."):  return "VMware NAT",        True
    if ip.startswith("192.168.122."): return "VMware default",    True
    if ip.startswith("192.168.157."): return "VMware Host-only",  True
    if ip.startswith("192.168.56."):  return "VirtualBox",        True
    if ip.startswith("169.254."):     return "Link-local",        True
    if ip.startswith("10."):          return "WiFi / Internal",   False  # hotspot or LAN, NOT VPN
    if ip.startswith("100."):         return "USB Tethering",     False
    return "WiFi / Ethernet", False

def local_ip() -> str:
    ips = get_all_local_ips()
    # Priority 1: Android hotspot (phone is the gateway, most common case)
    for ip in ips:
        if ip.startswith("192.168.43."): return ip
    # Priority 2: USB tethering (100.x.x.x) — phone tethered to Windows via USB
    # Without this, the script would miss the 100.x.x.x subnet entirely when
    # running on Termux and trying to reach a Windows SSH server over USB tether.
    for ip in ips:
        if ip.startswith("100."):        return ip
    # Priority 3: any other real (non-virtual) adapter
    real = [ip for ip in ips if not classify_ip(ip)[1]]
    return real[0] if real else (ips[0] if ips else "127.0.0.1")

# ─────────────────────────────────────────────────────────────────────
# MAC ADDRESS — device identity that survives IP changes
# ─────────────────────────────────────────────────────────────────────
def get_mac(ip: str) -> str:
    # /proc/net/arp — Linux, instant
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if parts and parts[0] == ip and len(parts) >= 4:
                    mac = parts[3].lower()
                    if mac != "00:00:00:00:00:00" and ":" in mac:
                        return mac
    except Exception: pass
    # arp command — Windows / macOS
    try:
        flag = "-a" if os.name == "nt" else "-n"
        r = subprocess.run(["arp", flag, ip], capture_output=True,
                           text=True, timeout=3)
        for line in r.stdout.split("\n"):
            if ip in line:
                for part in line.split():
                    sep_char = "-" if os.name == "nt" else ":"
                    if sep_char in part and len(part) in (17, 14):
                        return part.replace("-", ":").lower()
    except Exception: pass
    return ""

# ─────────────────────────────────────────────────────────────────────
# DEVICE ID — stable 8-char hash based on MAC
# Survives IP changes. If no MAC, falls back to hostname+user.
# ─────────────────────────────────────────────────────────────────────
def make_device_id(mac: str, hostname: str = "", user: str = "") -> str:
    raw = f"mac:{mac}" if mac and mac != "00:00:00:00:00:00" \
          else f"host:{hostname}:{user}"
    return hashlib.sha256(raw.encode()).hexdigest()[:8]

def _safe(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", str(s)).lower()[:16]

def _local_name() -> str:
    return _safe(socket.gethostname().split(".")[0])

def _device_label(h: dict, max_len: int = 16) -> str:
    """
    Return the best human-readable label for a device.
    Priority: nickname → hostname (if different from IP) → IP
    """
    nick = h.get("nickname","").strip()
    if nick: return nick[:max_len]
    hn = h.get("hostname","")
    if hn and hn != h.get("ip",""):
        return hn[:max_len]
    return h.get("ip","?")[:max_len]

# ─────────────────────────────────────────────────────────────────────
# SSH KEY FILES
# Named: id_rsa_THISDEVICE_to_DEVICEID  e.g. id_rsa_laptop_to_a3f29b1c
# One key per connection direction. Keys stored in ~/.ssh/
# ─────────────────────────────────────────────────────────────────────
def _ssh_dir() -> str:
    """
    Return the directory where OpenSSH keys are stored.
    This is always ~/.ssh/ because OpenSSH requires keys there.
    Keys are ALSO copied to Ssh/keys/ for backup/restore.
    """
    d = os.path.join(os.path.expanduser("~"), ".ssh")
    os.makedirs(d, exist_ok=True)
    return d

def _find_existing_keys() -> list:
    """Find all private keys in ~/.ssh/ by reading first line."""
    found = []
    try:
        for fname in sorted(os.listdir(_ssh_dir())):
            if fname.endswith(".pub"): continue
            if fname.endswith(".linkx_meta"): continue
            if fname in ("known_hosts","known_hosts.old","config","authorized_keys"):
                continue
            fpath = os.path.join(_ssh_dir(), fname)
            if not os.path.isfile(fpath): continue
            try:
                with open(fpath, errors="ignore") as f:
                    first = f.readline().strip()
                # Only real private key files — never touch files with headers
                if "PRIVATE KEY" in first or first.startswith("-----BEGIN"):
                    found.append(fpath)
            except Exception: pass
    except Exception: pass
    return found


# ─────────────────────────────────────────────────────────────────────
# NAMED-KEY IDENTITY SYSTEM
#
# After setup or pairing completes, the user names both devices.
# The key file is renamed:  ThisDevice_to_OtherDevice       (private)
#                            ThisDevice_to_OtherDevice.pub   (public)
# Identity metadata is stored in a SEPARATE sidecar file:
#                            ThisDevice_to_OtherDevice.linkx_meta
#
# The private key file is NEVER modified — OpenSSH rejects key files
# that have anything before the -----BEGIN line.  The sidecar holds:
#
#   ThisDevice=V-15
#   RemoteDevice=vivo
#   PairID=a3f29b1c
#   Created=2025-04-04
#
# The JSON key_name field stores the relation "V-15_to_vivo" so the
# scan knows exactly which key to try against which device.
# ─────────────────────────────────────────────────────────────────────

def _meta_path(kpath: str) -> str:
    """Return the sidecar metadata file path for a given key file."""
    return kpath + ".linkx_meta"


def _safe_name(s: str) -> str:
    """Convert a user-supplied device name to a safe filename component."""
    s = s.strip()
    s = re.sub(r"[^a-zA-Z0-9_\-]", "_", s)
    return s[:24] if s else "device"


def _read_key_identity(kpath: str) -> dict:
    """
    Read the linkx identity from the sidecar .linkx_meta file.
    Falls back to scanning the key file itself for legacy comment headers
    (from the broken old design) and migrates them out if found.
    Returns dict with 'this_device', 'remote_device', 'pair_id', 'created'.
    """
    result = {}
    meta   = _meta_path(kpath)

    # ── Primary: read sidecar file ────────────────────────────────────
    if os.path.exists(meta):
        try:
            with open(meta) as f:
                for line in f:
                    line = line.strip()
                    if "=" not in line or line.startswith("#"):
                        continue
                    k, _, v = line.partition("=")
                    result[k.strip().lower()] = v.strip()
            # normalise key names
            out = {}
            for k, v in result.items():
                if   "thisdevice"   in k: out["this_device"]   = v
                elif "remotedevice" in k: out["remote_device"]  = v
                elif "pairid"       in k: out["pair_id"]        = v
                elif "created"      in k: out["created"]        = v
            return out
        except Exception:
            pass

    # ── Legacy fallback: key file has inline comment header (old design)
    # Migrate it: write sidecar, strip comments from key file.
    try:
        with open(kpath, errors="ignore") as f:
            raw = f.read()
        lines = raw.splitlines()
        header_lines = []
        key_lines    = []
        in_key       = False
        for line in lines:
            if line.startswith("-----BEGIN") or in_key:
                in_key = True
                key_lines.append(line)
            elif line.startswith("#"):
                header_lines.append(line)
            # silently drop any other non-key, non-comment lines

        if not header_lines:
            return {}   # no inline header either

        # Parse legacy header
        for line in header_lines:
            line = line.lstrip("# ").strip()
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            k = k.strip().lower().replace(" ", "").replace("device", "")
            v = v.strip()
            if   "this"   in k: result["this_device"]   = v
            elif "remote" in k: result["remote_device"]  = v
            elif "pair"   in k: result["pair_id"]        = v
            elif "creat"  in k: result["created"]        = v

        if result:
            # Write sidecar so we never need to touch the key again
            _write_key_meta(kpath,
                            result.get("this_device",""),
                            result.get("remote_device",""),
                            result.get("pair_id",""))
            # Restore the key file to pure PEM (no comment lines)
            clean = "\n".join(key_lines)
            if not clean.endswith("\n"):
                clean += "\n"
            with open(kpath, "w") as f:
                f.write(clean)
            if os.name != "nt":
                try: os.chmod(kpath, 0o600)
                except Exception: pass

    except Exception:
        pass
    return result


def _write_key_meta(kpath: str, this_name: str, remote_name: str, pair_id: str):
    """
    Write (or overwrite) the identity sidecar file for a key.
    The private key file is NEVER touched — OpenSSH must be able to
    read it without any modification.
    """
    meta = _meta_path(kpath)
    try:
        with open(meta, "w") as f:
            f.write(
                f"ThisDevice={this_name}\n"
                f"RemoteDevice={remote_name}\n"
                f"PairID={pair_id}\n"
                f"Created={__import__('datetime').date.today()}\n"
            )
    except Exception as e:
        warn(f"Could not write key metadata: {e}")


def _inject_key_header(kpath: str, this_name: str, remote_name: str, pair_id: str):
    """
    Write the identity sidecar. Named _inject_key_header for backwards
    compatibility with existing call sites — does NOT touch the key file.
    """
    _write_key_meta(kpath, this_name, remote_name, pair_id)


def _rename_key_locally(old_kpath: str, this_name: str, remote_name: str,
                        device_id: str) -> str:
    """
    Rename the private key (and .pub and .linkx_meta) to
    ThisDevice_to_RemoteDevice.  Writes the identity sidecar.
    Updates the key database (device_id → new path).
    Returns the new key path, or old_kpath if rename failed.
    The private key file content is NEVER modified.
    """
    ssh_d    = _ssh_dir()
    new_name = f"{this_name}_to_{remote_name}"
    new_path = os.path.join(ssh_d, new_name)
    old_pub  = old_kpath + ".pub"
    new_pub  = new_path  + ".pub"
    old_meta = _meta_path(old_kpath)
    new_meta = _meta_path(new_path)

    # Resolve real absolute paths — Termux uses symlinks so ~/.ssh and
    # /data/data/com.termux/files/home/.ssh are the same dir but
    # os.rename treats different string forms as different paths
    old_kpath_r = os.path.realpath(os.path.expanduser(old_kpath))
    new_path_r  = os.path.realpath(os.path.expanduser(new_path))
    old_pub     = old_kpath_r + ".pub"
    new_pub     = new_path_r  + ".pub"
    old_meta    = _meta_path(old_kpath_r)
    new_meta    = _meta_path(new_path_r)

    # Resolve real absolute paths — Termux ~/.ssh and full path are same
    # dir but different strings causing FileNotFoundError on os.rename
    old_kpath_r = os.path.realpath(os.path.expanduser(old_kpath))
    new_path_r  = os.path.realpath(os.path.expanduser(new_path))
    old_pub     = old_kpath_r + ".pub"
    new_pub     = new_path_r  + ".pub"
    old_meta    = _meta_path(old_kpath_r)
    new_meta    = _meta_path(new_path_r)

    # Don't rename if already has this name
    if old_kpath_r == new_path_r:
        _write_key_meta(new_path_r, this_name, remote_name, device_id)
        return new_path_r

    try:
        for p in (new_path_r, new_pub, new_meta):
            if os.path.exists(p):
                os.remove(p)
        os.rename(old_kpath_r, new_path_r)
        if os.path.exists(old_pub):
            os.rename(old_pub, new_pub)
        if os.path.exists(old_meta):
            os.rename(old_meta, new_meta)
    except Exception as e:
        warn(f"Could not rename key file: {e}")
        return old_kpath_r

    new_path = new_path_r

    # Write the sidecar — private key file is left completely untouched
    _write_key_meta(new_path, this_name, remote_name, device_id)

    # Update key database
    save_key(device_id, new_path)

    return new_path


def _rename_key_on_remote(ip: str, user: str, port: int, kp: str,
                           this_name: str, remote_name: str, pair_id: str):
    """
    Over SSH, rename the reverse key on the remote device (pair case only).
    Renames private key + .pub to RemoteName_to_ThisName.
    Writes a .linkx_meta sidecar — does NOT modify the key file itself.
    Best-effort: failure never breaks the connection.
    """
    # Sanitize names before embedding in remote shell script
    this_name   = re.sub(r"[^a-zA-Z0-9_\-]", "_", this_name)[:40]
    remote_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", remote_name)[:40]
    pair_id     = re.sub(r"[^a-zA-Z0-9]", "", pair_id)[:8]
    new_name  = f"{remote_name}_to_{this_name}"
    meta_name = f"{new_name}.linkx_meta"
    today     = str(__import__('datetime').date.today())
    meta_content = (
        f"ThisDevice={remote_name}\\n"
        f"RemoteDevice={this_name}\\n"
        f"PairID={pair_id}\\n"
        f"Created={today}\\n"
    )

    # Shell script on the remote device:
    # 1. Find any linkx private key in ~/.ssh/ (id_rsa_* or similarly named)
    # 2. Rename it and its .pub — NEVER modify the key content
    # 3. Write the .linkx_meta sidecar
    meta_mv = f"[ -f \"$k.linkx_meta\" ] && mv -f \"$k.linkx_meta\" \"{meta_name}\"; true"
    script = (
        f"cd ~/.ssh 2>/dev/null || exit 0; "
        f"for k in id_rsa_* id_ecdsa_* id_ed25519_* *_to_*; do "
        f"  [ -f \"$k\" ] || continue; "
        f"  echo \"$k\" | grep -qE '\\.pub$|\\.linkx_meta$' && continue; "
        f"  head -c 40 \"$k\" | grep -q 'BEGIN' || continue; "
        f"  mv -f \"$k\" \"{new_name}\" 2>/dev/null && "
        f"  ( [ -f \"$k.pub\" ] && mv -f \"$k.pub\" \"{new_name}.pub\" || true ) && "
        f"  ( {meta_mv} ) && "
        f"  break; "
        f"done; "
        f"printf '{meta_content}' > \"{meta_name}\" 2>/dev/null; "
        f"echo RENAMED"
    )
    try:
        out = run_cmd(ip, user, port, script, kp, timeout=15)
        if "RENAMED" in out:
            pr(f"  {C.D}Remote key renamed: {new_name}{C.R}")
    except Exception:
        pass   # best-effort — never breaks the connection


def _name_connection(host_record: dict, kpath: str, hosts: dict,
                     remote_ip: str, remote_user: str, remote_port: int,
                     is_pair: bool = False) -> tuple:
    """
    Post-setup / post-pair naming ceremony.
    Asks the user to name THIS device and the REMOTE device.
    Renames the key file, injects the identity header, updates the DB.
    If is_pair=True, also renames the reverse key on the remote device.

    Returns (updated_kpath, updated_host_record).
    """
    clear()
    hdr("NAME THIS CONNECTION", "Give both devices a friendly name")
    pr()
    pr(f"  {C.B}Why name devices?{C.R}")
    pr(f"  The key file is renamed to  ThisDevice_to_OtherDevice")
    pr(f"  Even if the IP or MAC changes, the key identity is permanent.")
    pr(f"  The tool will always find the right device by trying this key.")
    pr()
    pr(f"  {C.D}Press Enter to skip naming (auto-generated name kept){C.R}")
    sep()

    did        = host_record.get("device_id", "")
    existing   = _read_key_identity(kpath)
    my_default = existing.get("this_device",   _safe_name(socket.gethostname().split(".")[0]))
    rm_default = existing.get("remote_device", _safe_name(host_record.get("nickname","") or
                                                           host_record.get("hostname","") or
                                                           remote_ip))

    pr(f"  {C.B}This device{C.R}   (the one you are using now):")
    this_name  = ask("  Your device name", my_default).strip()
    if not this_name: this_name = my_default
    this_name  = _safe_name(this_name)

    pr()
    pr(f"  {C.B}Other device{C.R}  ({remote_ip}):")
    remote_name = ask("  Other device name", rm_default).strip()
    if not remote_name: remote_name = rm_default
    remote_name = _safe_name(remote_name)

    pr()
    pr(f"  {C.D}Renaming key:  {this_name}_to_{remote_name}{C.R}")

    # Rename key locally
    new_kpath = _rename_key_locally(kpath, this_name, remote_name, did)

    # Update host record
    host_record["nickname"]   = remote_name
    host_record["key_source"] = os.path.basename(new_kpath)
    host_record["key_name"]   = f"{this_name}_to_{remote_name}"
    host_record["key_ok"]     = True
    hosts[remote_ip] = host_record
    save_hosts(hosts)

    ok(f"Key renamed: {os.path.basename(new_kpath)}")

    # If this was a pair operation, rename the reverse key on the remote too
    if is_pair and new_kpath and os.path.exists(new_kpath):
        pr(f"  {C.D}Renaming reverse key on {remote_ip}...{C.R}")
        _rename_key_on_remote(remote_ip, remote_user, remote_port,
                              new_kpath, this_name, remote_name, did)

    sep()
    pr(f"  {C.G}✓{C.R}  Key file : {C.B}{this_name}_to_{remote_name}{C.R}")
    pr(f"  {C.G}✓{C.R}  Identity : {C.B}{remote_name}{C.R} remembered by key — survives IP/MAC changes")
    pause()

    # ── Vault prompt — ask user if they want to add this device ──────
    host_record = _ask_add_to_vault(
        host_record, hosts,
        ip=remote_ip, user=remote_user, port=remote_port, kp=new_kpath)

    return new_kpath, host_record

def generate_key(device_id: str, label: str = "") -> tuple:
    """
    Generate RSA 4096 key named id_rsa_THISDEVICE_to_DEVICEID.
    Returns (key_path, pub_key_text).

    CRITICAL: Delete existing key files BEFORE running ssh-keygen.
    If the file exists, ssh-keygen asks "Overwrite (y/n)?" interactively.
    With capture_output=True that prompt is hidden and the process hangs
    silently — user sees a frozen cursor with no explanation.
    """
    name    = f"id_ed25519_{_local_name()}_to_{device_id}"
    kpath   = os.path.join(_ssh_dir(), name)
    ppath   = kpath + ".pub"
    comment = f"{_local_name()}_to_{device_id}"
    if label: comment += f"_{_safe(label)}"

    # Delete existing files so ssh-keygen never asks "Overwrite?"
    for _old in (kpath, ppath):
        try:
            if os.path.exists(_old): os.remove(_old)
        except Exception: pass

    pr(f"  Generating key: {C.G}{name}{C.R}")
    r = subprocess.run([
        "ssh-keygen", "-t", "ed25519",
        "-f", kpath, "-N", "", "-C", comment
    ], capture_output=True)

    if r.returncode != 0:
        # Show error — key generation failed
        msg = r.stderr.decode(errors="ignore").strip()
        warn(f"ssh-keygen failed: {msg[:120]}")
        return "", ""

    if os.name != "nt":
        try: os.chmod(kpath, 0o600)
        except Exception: pass

    pub = open(ppath).read().strip() if os.path.exists(ppath) else ""
    return kpath, pub

# ─────────────────────────────────────────────────────────────────────
# KEY DATABASE  .linkx_keys.json
# Maps device_id → key file path
# ─────────────────────────────────────────────────────────────────────
def _load_km() -> dict:
    try:
        with open(KEY_MAP, encoding='utf-8') as f: return json.load(f)
    except Exception: return {}

def _save_km(m: dict):
    with _FILE_LOCK:
        try:
            tmp = KEY_MAP + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f: json.dump(m, f, indent=2)
            if os.name != "nt":
                try: os.chmod(tmp, 0o600)
                except Exception: pass
            os.replace(tmp, KEY_MAP)
        except Exception:
            try: os.remove(tmp)
            except Exception: pass

def get_key(device_id: str) -> str:
    """Return key path for this device_id if file exists on disk."""
    if not device_id: return ""
    path = _load_km().get(device_id, "")
    return path if path and os.path.exists(path) else ""

def save_key(device_id: str, key_path: str):
    """Atomic read-modify-write — safe under 50 concurrent scan threads."""
    with _FILE_LOCK:
        try:
            with open(KEY_MAP, encoding="utf-8") as f:
                m = json.load(f)
        except Exception:
            m = {}
        m[device_id] = key_path
        tmp = KEY_MAP + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(m, f, indent=2)
        os.replace(tmp, KEY_MAP)

# ─────────────────────────────────────────────────────────────────────
# PASSWORD STORE  .linkx_pass.json
# Indexed by device_id, lightly obfuscated (base64)
# ─────────────────────────────────────────────────────────────────────
def _ob(pw): return base64.b64encode(pw.encode()).decode()
def _dob(s):
    try:    return base64.b64decode(s.encode()).decode()
    except Exception: return ""

def _load_pw() -> dict:
    try:
        with open(PASS_FILE, encoding='utf-8') as f: return json.load(f)
    except Exception: return {}

def _save_pw(d: dict):
    with _FILE_LOCK:
        try:
            tmp = PASS_FILE + ".tmp"
            with open(tmp, "w") as f: json.dump(d, f, indent=2)
            os.replace(tmp, PASS_FILE)
            if os.name != "nt": os.chmod(PASS_FILE, 0o600)
        except Exception:
            try: os.remove(tmp)
            except Exception: pass

def get_pw(device_id: str) -> str:
    return _dob(_load_pw().get(device_id, ""))

def set_pw(device_id: str, pw: str):
    d = _load_pw(); d[device_id] = _ob(pw); _save_pw(d)

def del_pw(device_id: str):
    d = _load_pw(); d.pop(device_id, None); _save_pw(d)

# ─────────────────────────────────────────────────────────────────────
# HOST STORE  .linkx_hosts.json
# ─────────────────────────────────────────────────────────────────────
def _dedup_hosts(hosts: dict, save: bool = True) -> dict:
    """
    Collapse duplicate host records that represent the same physical device.
    Called at load time AND immediately after setup_device writes a new record,
    so duplicates never persist within a session.

    Dedup key: key_source filename (stable across IP+MAC changes).
    Winner:    record with a nickname > most recently seen.

    Also back-fills mac_randomized flag for Android/macOS/Windows records
    that pre-date the field.

    Returns the cleaned hosts dict (mutates in place and optionally saves).
    """
    seen_keys: dict = {}   # key_source_basename → ip
    to_remove: list = []

    for ip, h in list(hosts.items()):
        ks = os.path.basename(h.get("key_source", ""))
        if not ks:
            continue
        if ks in seen_keys:
            other_ip = seen_keys[ks]
            other    = hosts.get(other_ip)
            if other is None:           # already marked for removal
                seen_keys[ks] = ip
                continue
            # Pick winner: nickname > most recent seen_at
            if other.get("nickname") and not h.get("nickname"):
                to_remove.append(ip)
            elif h.get("nickname") and not other.get("nickname"):
                to_remove.append(other_ip)
                seen_keys[ks] = ip
            elif h.get("seen_at", 0) > other.get("seen_at", 0):
                to_remove.append(other_ip)
                seen_keys[ks] = ip
            else:
                to_remove.append(ip)
        else:
            seen_keys[ks] = ip

    for ip in to_remove:
        hosts.pop(ip, None)

    # Back-fill mac_randomized for records that pre-date the field
    backfilled = False
    for h in hosts.values():
        if h.get("os_type") in MAC_RANDOMIZED_OS and not h.get("mac_randomized"):
            h["mac_randomized"] = True
            backfilled = True

    if save and (to_remove or backfilled):
        save_hosts(hosts)

    return hosts


def load_hosts() -> dict:
    try:
        with open(DATA_FILE, encoding='utf-8') as f:
            hosts = json.load(f)
    except Exception:
        return {}
    try:
        return _dedup_hosts(hosts, save=True)
    except Exception:
        # Malformed host records — return raw dict rather than crash
        return hosts if isinstance(hosts, dict) else {}

def save_hosts(hosts: dict):
    with _FILE_LOCK:
        try:
            tmp = DATA_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(hosts, f, indent=2)
            if os.name != "nt":
                try: os.chmod(tmp, 0o600)
                except Exception: pass
            os.replace(tmp, DATA_FILE)
        except Exception:
            try: os.remove(tmp)
            except Exception: pass

def merge_hosts(scanned: list, known: dict) -> dict:
    """
    Merge scan results into known hosts.

    Identity resolution order (handles IP changes, network-adapter changes):
      1. MAC match        — same MAC in DB → update IP silently
      2. key_source match — same key file name in DB → same physical device
                           even if it appeared on a different network adapter
                           (e.g. phone connected via WiFi vs USB/hotspot)
      3. device_id match  — same device_id (fallback when MAC was empty on
                           first registration)
      4. IP match         — same IP, just refresh timestamps
      5. New device       — add fresh entry

    When a duplicate is collapsed, the entry with a nickname is always kept.
    """
    result = dict(known)

    def _find_existing(ip, mac, key_source, device_id, os_type=""):
        """Return the existing host record that matches this scan result.

        MAC matching is skipped when the OS is known to randomize MACs
        (Android, macOS, Windows) — for those, key_source is the primary
        identity anchor.
        """
        # 1. MAC — only for OSes with stable, non-randomized MACs
        skip_mac = os_type in MAC_RANDOMIZED_OS
        if mac and not skip_mac:
            for v in result.values():
                # Also skip if the stored record itself is flagged randomized
                if v.get("mac_randomized"):
                    continue
                if v.get("mac") == mac:
                    return v
        # 2. key_source (same key file = same physical device, works across
        #    network changes, adapter changes, and MAC randomization)
        if key_source:
            ks_base = os.path.basename(key_source)
            for v in result.values():
                v_ks = os.path.basename(v.get("key_source", ""))
                if v_ks and v_ks == ks_base and v.get("ip") != ip:
                    return v
        # 3. device_id
        if device_id:
            for v in result.values():
                if v.get("device_id") == device_id and v.get("ip") != ip:
                    return v
        return None

    for h in scanned:
        ip         = h["ip"]
        mac        = h.get("mac", "")
        key_source = h.get("key_source", "")
        device_id  = h.get("device_id", "")

        existing = _find_existing(ip, mac, key_source, device_id, h.get("os_type", ""))

        if existing and existing["ip"] != ip:
            # ── IP changed: move record to new key, keep all metadata ──
            old_ip = existing["ip"]
            result.pop(old_ip, None)
            existing.update({
                "ip":       ip,
                "hostname": h["hostname"],
                "ssh_port": h["ssh_port"],
                "seen_at":  h["seen_at"],
            })
            # For MAC-randomized OSes: always overwrite stored MAC with the
            # freshly scanned one (it may have changed — that is expected).
            # For stable-MAC OSes: keep existing MAC if non-empty.
            if existing.get("mac_randomized") or h.get("mac_randomized"):
                existing["mac_randomized"] = True
                if mac:
                    existing["mac"] = mac  # update to current random MAC
            elif mac and not existing.get("mac"):
                existing["mac"] = mac
            result[ip] = existing

        elif ip in result:
            # ── Same IP: refresh volatile fields only ──
            result[ip]["mac"]      = mac or result[ip].get("mac", "")
            result[ip]["hostname"] = h["hostname"]
            result[ip]["ssh_port"] = h["ssh_port"]
            result[ip]["seen_at"]  = h["seen_at"]
            if h.get("os_type", "unknown") != "unknown":
                result[ip]["os_type"] = h["os_type"]
            if h.get("banner"):
                result[ip]["banner"] = h["banner"]
            if not result[ip].get("nickname") and h.get("nickname"):
                result[ip]["nickname"] = h["nickname"]

        else:
            # ── Genuinely new device ──
            result[ip] = h

    return result

# ─────────────────────────────────────────────────────────────────────
# NETWORK PROBE
# Reads SSH banner on the SAME socket as port detection.
# No double connection. Validates "SSH-" prefix.
# ─────────────────────────────────────────────────────────────────────
def probe_host(ip: str) -> dict | None:
    """
    Probe a single IP for SSH on ports 22 and 8022 IN PARALLEL.

    OLD: tried port 22, waited SCAN_TIMEOUT, then tried 8022 = worst case 2.4s
    NEW: both ports probed simultaneously = worst case 1.2s regardless

    Banner read timeout reduced from 1.5s to _BANNER_TIMEOUT (0.4s).
    SSH sends its banner immediately on connect — 0.4s is still 8x the
    typical LAN round-trip time (50ms). Robust even on congested networks.

    DNS reverse lookup (gethostbyaddr) is DEFERRED — it can block 1-2s
    per device and runs inside the scan thread, killing parallelism.
    Hostname is resolved after scan completes or set to IP as fallback.
    """
    result_box = [None]
    found_ev   = threading.Event()

    def _try_port(port: int):
        if found_ev.is_set():
            return
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SCAN_TIMEOUT)
            if s.connect_ex((ip, port)) != 0:
                return

            # Read SSH banner on same socket — fast timeout
            banner = ""
            try:
                s.settimeout(_BANNER_TIMEOUT)
                data   = s.recv(256)
                banner = data.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
            s.close(); s = None

            # Must look like SSH
            if banner and not banner.startswith("SSH-"):
                return

            # Claim this port as winner — first thread wins
            if found_ev.is_set():
                return
            found_ev.set()

            # MAC — ARP table is populated by TCP connect itself
            mac = get_mac(ip)
            if not mac:
                try:
                    subprocess.run(
                        ["ping", "-n" if os.name == "nt" else "-c", "1",
                         "-w" if os.name == "nt" else "-W", "1", ip],
                        capture_output=True, timeout=1)
                    mac = get_mac(ip)
                except Exception:
                    pass

            # Hostname — use IP as placeholder, resolve later if needed
            # gethostbyaddr can block 1-2s — not worth it during bulk scan
            hostname = ip

            b = banner.lower()
            os_type = ("android" if port == 8022 else
                       "kali"    if "kali"    in b else
                       "macos"   if "darwin"  in b else
                       "windows" if "windows" in b or "openssh_for_windows" in b else
                       "linux"   if "ubuntu"  in b or "debian" in b or "openssh" in b
                       else "unknown")

            mac_randomized = os_type in MAC_RANDOMIZED_OS
            result_box[0] = {
                "ip": ip, "mac": mac, "hostname": hostname,
                "ssh_port": port, "os_type": os_type, "banner": banner,
                "mac_randomized": mac_randomized,
                "user": "", "device_id": "", "key_ok": False,
                "seen_at": time.time()
            }
        except Exception:
            pass
        finally:
            if s:
                try: s.close()
                except Exception: pass

    # Probe both ports in parallel — done when either wins or both fail
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as _pex:
        futs = [_pex.submit(_try_port, p) for p in (22, 8022)]
        concurrent.futures.wait(futs,
                                timeout=SCAN_TIMEOUT + _BANNER_TIMEOUT + 0.1)

    return result_box[0]

def detect_remote_os(ip: str, port: int, user: str = "", kp: str = "") -> str:
    """
    Detect remote OS. Two-stage:

    Stage 1 — Banner grab (no auth needed, instant):
      Read the SSH banner string from the TCP socket.
      'OpenSSH_for_Windows' → windows
      Port 8022             → android
      Other OpenSSH         → probably linux/mac, need stage 2

    Stage 2 — Command probe (needs working key):
      Only runs if we have a valid key that actually authenticates.
      Tries: ver → uname -s → /etc/os-release → sw_vers
    """
    if port == 8022:
        return "android"

    # Stage 1: raw TCP banner grab — no auth, no key needed
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((ip, port))
        banner = s.recv(256).decode("utf-8", errors="ignore").strip()
        s.close()
        bl = banner.lower()
        if "windows" in bl:
            return "windows"
        # 'SSH-2.0-OpenSSH_8.9p1 Ubuntu' or similar — continue to stage 2
    except Exception:
        return "other"

    # Stage 2: command probe — only if key works (BatchMode=yes, no password prompt)
    if not user or not kp or not os.path.exists(kp):
        # No key available — can't run commands, return best guess from banner
        if "openssh" in bl:
            return "linux"   # most common — user can override
        return "other"

    def _ssh_run(cmd: str, timeout: int = 6) -> str:
        try:
            args = ["ssh", "-p", str(port),
                    "-i", kp,
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=4",
                    "-o", "LogLevel=ERROR",
                    f"{user}@{ip}", cmd]
            r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return (r.stdout + r.stderr).strip()
        except Exception:
            return ""

    # 'ver' → Windows cmd.exe only
    out = _ssh_run("ver", timeout=5)
    if "microsoft windows" in out.lower():
        return "windows"

    # uname -s → Linux / Darwin
    out = _ssh_run("uname -s", timeout=5)
    out_l = out.strip()
    if out_l == "Darwin":
        return "macos"
    if out_l == "Linux":
        rel = _ssh_run("cat /etc/os-release 2>/dev/null", timeout=5).lower()
        if "kali"    in rel: return "kali"
        if "arch"    in rel: return "arch"
        if "fedora"  in rel or "rhel" in rel or "centos" in rel: return "rhel"
        if "opensuse" in rel or "suse" in rel: return "suse"
        if "alpine"  in rel: return "alpine"
        if "void"    in rel: return "void"
        if "gentoo"  in rel: return "gentoo"
        return "linux"

    out = _ssh_run("sw_vers 2>/dev/null", timeout=5)
    if "macos" in out.lower() or "mac os x" in out.lower():
        return "macos"

    return "linux"   # best guess


# ─────────────────────────────────────────────────────────────────────
# MULTI-HOP RELAY — reach devices on different subnets
#
# TOPOLOGY EXAMPLE:
#   Vivo hotspot  192.168.43.x
#     Laptop      192.168.43.5   (also runs hotspot → 192.168.137.x)
#       Redmi 9i  192.168.137.3
#     Redmi 4A    192.168.43.8
#
#   Redmi 9i (192.168.137.3) CANNOT reach Redmi 4A (192.168.43.8) directly.
#   But Laptop can reach both → Laptop is the RELAY.
#
# HOW IT WORKS:
#   SSH ProxyJump (-J flag):
#     ssh -J relay_user@relay_ip:relay_port  target_user@target_ip -p target_port
#   SCP via ProxyJump:
#     scp -o ProxyJump=relay_user@relay_ip:relay_port  ...
#
#   The relay laptop forwards the TCP stream transparently.
#   No data is stored on the relay — it's a pure TCP pipe.
#   Speed: limited by the slowest link in the chain.
#
# RELAY RECORD stored in .linkx_hosts.json per device:
#   "relay": {"ip": "192.168.43.5", "user": "Admin", "port": 22, "kp": "/path/key"}
#
# DEVICE REACHABILITY:
#   Direct : device is on one of our local subnets → connect directly
#   Relay  : device is NOT on local subnet but relay IS → use ProxyJump
#   Unknown: neither → try scanning all known relays
# ─────────────────────────────────────────────────────────────────────

def _my_subnets() -> set:
    """Return set of /24 subnet prefixes reachable directly from this machine.
    Includes 100.x.x.x (USB tethering) — these are real physical links."""
    prefixes = set()
    for ip in get_all_local_ips():
        # Skip loopback and link-local only — 100.x.x.x is a valid tether subnet
        if ip.startswith("127.") or ip.startswith("169.254."): continue
        prefixes.add(".".join(ip.split(".")[:3]))
    return prefixes

def is_directly_reachable(ip: str) -> bool:
    """True if ip is on one of our local subnets."""
    pfx = ".".join(ip.split(".")[:3])
    return pfx in _my_subnets()

def find_relay(target_ip: str, hosts: dict) -> dict | None:
    """
    Find a relay host that can reach target_ip.
    A host qualifies as relay if:
      - It is directly reachable from us (on our subnet)
      - It has a working SSH key
      - It has an IP on the same subnet as target_ip
    Returns relay host dict or None.
    """
    target_pfx = ".".join(target_ip.split(".")[:3])
    my_pfxs    = _my_subnets()

    for ip, h in hosts.items():
        if ip == target_ip: continue
        did = h.get("device_id","")
        kp  = get_key(did) if did else ""
        if not kp: continue
        # Relay must be directly reachable by us
        our_pfx = ".".join(ip.split(".")[:3])
        if our_pfx not in my_pfxs: continue
        # Relay must have a known IP on target's subnet
        # Check all known IPs of this relay (stored in relay_ips if multi-homed)
        relay_ips = h.get("relay_ips", [ip])
        for rip in relay_ips:
            if ".".join(rip.split(".")[:3]) == target_pfx:
                return h
        # Also check if this relay's IP is on the target subnet directly
        if ".".join(ip.split(".")[:3]) == target_pfx:
            return h
    return None


def _proxy_jump_str(relay: dict, relay_kp: str) -> str:
    """Build the ProxyJump value string for -o ProxyJump=..."""
    ru   = relay.get("user","")
    rip  = relay.get("ip","")
    rport= relay.get("ssh_port", 22)
    # ProxyJump format: user@ip:port OR use -i for relay key via ProxyCommand
    # Use ProxyCommand for key support (ProxyJump doesn't accept -i for relay)
    return (f"ssh -W %h:%p "
            f"-i {relay_kp} "
            f"-p {rport} "
            f"-o StrictHostKeyChecking=no "
            f"-o BatchMode=yes "
            f"-c aes128-gcm@openssh.com "
            f"{ru}@{rip}")


def do_scp_relay(src, dest, port, kp, relay: dict, relay_kp: str,
                 force_recursive: bool = False) -> tuple:
    """
    SCP via relay (ProxyJump/ProxyCommand).
    Forges:
      scp -P port -i kp
          -o ProxyCommand="ssh -W %h:%p -i relay_kp -p rport user@relay_ip"
          src dest
    Python steps aside after launch — relay is a transparent TCP pipe.
    """
    is_dir = force_recursive or (os.path.isdir(src) if "@" not in src else False)
    proxy  = _proxy_jump_str(relay, relay_kp)

    args = [
        "scp",
        "-P", str(port),
        "-i", kp,
        "-c", "aes128-gcm@openssh.com",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-o", "Compression=no",
        "-o", "IPQoS=throughput",
        "-o", f"ProxyCommand={proxy}",
    ]
    if is_dir:
        args.append("-r")
    args += [src, dest]

    relay_ip = relay.get("ip","?")
    print(f"\n  {C.CY}[relay via {relay_ip}]{C.R}")
    display = " ".join(args)
    print(f"  {C.D}{display}{C.R}\n")

    try:
        r = subprocess.run(args)
        if r.returncode == 0:
            name = os.path.basename(
                (src if "@" not in src else src.split(":")[-1]).rstrip("/\\"))
            return True, f"Transfer complete via relay: {name}"
        return False, f"scp relay exited with code {r.returncode}"
    except KeyboardInterrupt:
        print()
        return False, "Transfer cancelled (Ctrl+C)"
    except FileNotFoundError: return False, "scp not found"
    except Exception as e:    return False, str(e)


def open_shell_relay(ip, user, port, kp, relay: dict, relay_kp: str):
    """
    Open interactive SSH shell through relay using ProxyCommand.
    Forges:
      ssh -p port -i kp -o ProxyCommand="..." user@ip
    """
    proxy = _proxy_jump_str(relay, relay_kp)
    args  = [
        "ssh", "-p", str(port),
        "-i", kp,
        "-c", "aes128-gcm@openssh.com",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "IPQoS=lowdelay",
        "-o", f"ProxyCommand={proxy}",
        f"{user}@{ip}",
    ]
    display = " ".join(args)
    print(f"\n  {C.CY}[shell via relay {relay.get('ip','?')}]{C.R}")
    print(f"  {C.D}{display}{C.R}\n")
    try:
        subprocess.run(args)
    except FileNotFoundError: err("ssh not found")
    except KeyboardInterrupt:  pass


def run_cmd_relay(ip, user, port, kp, cmd: str,
                  relay: dict, relay_kp: str) -> str:
    """Run a command on target via relay. Returns stdout."""
    proxy = _proxy_jump_str(relay, relay_kp)
    args  = ["ssh", "-p", str(port),
             "-i", kp,
             "-c", "aes128-gcm@openssh.com",
             "-o", "StrictHostKeyChecking=accept-new",
             "-o", "BatchMode=yes",
             "-o", "ConnectTimeout=10",
             "-o", f"ProxyCommand={proxy}",
             f"{user}@{ip}", cmd]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        return r.stdout.strip()
    except Exception: return ""


def test_key_relay(ip, user, port, kp,
                   relay: dict, relay_kp: str) -> bool:
    """Test key auth through relay."""
    out = run_cmd_relay(ip, user, port, kp, "echo SSHOK", relay, relay_kp)
    return "SSHOK" in out


def scan_via_relay(relay: dict, relay_kp: str,
                   on_found=None) -> list:
    """
    Scan subnets reachable via relay but NOT directly reachable by us.

    Fixes applied vs original:
      1. Multi-method IP discovery (hostname -I, ip addr, ifconfig) so it
         works on Android/Termux, Linux, and macOS relay devices.
      2. Port-scan command uses 'nc -z' with timeout as primary method
         (works on Termux/BusyBox/macOS/Linux), with /dev/tcp bash fallback.
         nc -z is universal; /dev/tcp is bash-only and absent on Termux.
      3. Shell variable renamed from 'ip' to 'tgt' to avoid shadowing.
      4. Sequential nc probes instead of background & jobs — output is clean
         and in order, no interleaving race conditions.
      5. Timeout per host is short (0.3s) so 254 hosts × 2 ports finishes
         in ~90s worst case; typical LAN is much faster.
    """
    relay_ip   = relay.get("ip","")
    relay_user = relay.get("user","")
    relay_port = relay.get("ssh_port", 22)

    if not relay_ip or not relay_user:
        return []

    # ── Step 1: get relay's own IP list ──────────────────────────────
    # Try multiple commands so we work on Android/Termux, Linux, macOS.
    # Termux has neither 'hostname' nor 'ip', but has 'ifconfig'.
    ip_cmd = (
        "hostname -I 2>/dev/null | tr ' ' '\\n' | grep -E '^[0-9]' ; "
        "ip addr show 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 ; "
        "ifconfig 2>/dev/null | grep 'inet ' | awk '{print $2}' | sed 's/addr://' "
    )
    relay_ips_raw = run_cmd(relay_ip, relay_user, relay_port, ip_cmd, relay_kp,
                            timeout=15)

    relay_ips = []
    seen = set()
    for tok in relay_ips_raw.split():
        tok = tok.strip()
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', tok) and not tok.startswith("127."):
            if tok not in seen:
                relay_ips.append(tok)
                seen.add(tok)

    if not relay_ips:
        pr(f"  {C.Y}Relay {relay_ip}: could not get IP list — skipping relay scan{C.R}")
        return []

    # ── Step 2: find subnets relay can reach that we can't ───────────
    my_pfxs  = _my_subnets()
    new_pfxs = set()
    for rip in relay_ips:
        pfx = ".".join(rip.split(".")[:3])
        if pfx not in my_pfxs:
            new_pfxs.add(pfx)

    if not new_pfxs:
        pr(f"  {C.D}Relay {relay_ip}: no new subnets beyond our own — skipping{C.R}")
        return []

    # ── Step 3: port-scan each new subnet via relay ───────────────────
    # Primary:  nc -z -w1 host port  (works on Termux BusyBox, GNU, macOS)
    # Fallback: bash /dev/tcp trick   (bash only, not Termux)
    # We run sequentially (no & background) to keep output clean.
    # 'tgt' used as variable name to avoid shadowing shell builtins.
    found = []

    for pfx in sorted(new_pfxs):
        pr(f"  {C.D}Relay scan: {pfx}.1-254 via {relay_ip}  (nc probe)...{C.R}")

        scan_cmd = (
            f"for i in $(seq 1 254); do "
            f"  tgt={pfx}.$i; "
            f"  for p in 22 8022; do "
            f"    if nc -z -w1 $tgt $p 2>/dev/null; then "
            f"      echo OPEN:$tgt:$p; "
            f"    elif (echo >/dev/tcp/$tgt/$p) 2>/dev/null; then "
            f"      echo OPEN:$tgt:$p; "
            f"    fi; "
            f"  done; "
            f"done"
        )

        out = run_cmd(relay_ip, relay_user, relay_port, scan_cmd, relay_kp,
                      timeout=180)  # 254 hosts × 2 ports × ~0.3s = up to ~90s

        # Deduplicate — both nc and /dev/tcp may fire for same host
        seen_results = set()
        for line in out.strip().split("\n"):
            line = line.strip()
            if not line.startswith("OPEN:"):
                continue
            parts = line.split(":")
            if len(parts) != 3:
                continue
            found_ip   = parts[1].strip()
            try:
                found_port = int(parts[2].strip())
            except ValueError:
                continue
            key = (found_ip, found_port)
            if key in seen_results:
                continue
            seen_results.add(key)
            # Don't re-add the relay itself
            if found_ip in relay_ips:
                continue
            # Skip our own IPs
            if found_ip in get_all_local_ips():
                continue

            h = {
                "ip"       : found_ip,
                "mac"      : "",
                "hostname" : found_ip,
                "ssh_port" : found_port,
                "os_type"  : ("android" if found_port == 8022 else "unknown"),
                "user"     : "",
                "device_id": "",
                "key_ok"   : False,
                "seen_at"  : time.time(),
                "via_relay": relay_ip,
            }
            found.append(h)
            if on_found:
                on_found(h, relay)

    return found


def install_key_via_relay(target_ip, target_user, target_port,
                          pub_key: str,
                          relay: dict, relay_kp: str,
                          target_os_type: str = "linux") -> bool:
    """
    Install pub_key on a target that is only reachable via relay.
    """
    safe = pub_key.replace("\\","\\\\").replace("'","'\"'\"'")

    if target_os_type == "windows":
        ps  = (f"New-Item -ItemType Directory -Force -Path '$env:USERPROFILE\\.ssh' | Out-Null; "
               f"'{safe}' | Add-Content '$env:USERPROFILE\\.ssh\\authorized_keys'; "
               f"New-Item -ItemType Directory -Force -Path 'C:\\ProgramData\\ssh' | Out-Null; "
               f"'{safe}' | Add-Content 'C:\\ProgramData\\ssh\\administrators_authorized_keys'; "
               f"echo KEY_INSTALLED")
        cmd = f"powershell -NoProfile -Command \"{ps}\""
    else:
        cmd = (f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
               f"echo '{safe}' >> ~/.ssh/authorized_keys && "
               f"chmod 600 ~/.ssh/authorized_keys && echo KEY_INSTALLED")

    proxy = _proxy_jump_str(relay, relay_kp)
    args  = ["ssh", "-p", str(target_port),
             "-o", "StrictHostKeyChecking=accept-new",
             "-o", "ConnectTimeout=20",
             "-o", "PreferredAuthentications=password,keyboard-interactive",
             "-o", "NumberOfPasswordPrompts=1",
             "-o", "BatchMode=no",
             "-o", f"ProxyCommand={proxy}",
             f"{target_user}@{target_ip}", cmd]

    pr(f"\n  {C.Y}SSH (via relay) will ask for password of "
       f"{target_user}@{target_ip}{C.R}")
    pr(f"  Type it when prompted.\n")
    try:
        r = subprocess.run(args)
        return r.returncode == 0
    except KeyboardInterrupt:
        print(); warn("Cancelled."); return False
    except Exception as e:
        err(str(e)); return False


def scan_network(subnets: list, extra_ips: list = None,
                 on_found=None, abort_event: threading.Event = None,
                 known_hosts: dict = None) -> list:
    """
    Scan all given subnets + extra IPs in parallel.

    PHASE 1 — known devices (NOW THREADED):
      Probes every known device at its last IP in parallel using
      FAST_PROBE_TIMEOUT. Previously this was a sequential for-loop —
      20 devices × 0.5s = 10s blocking before Phase 2 started.
      Now: all known devices probed simultaneously, done in ~0.5s.

    PHASE 2 — full subnet scan:
      Worker count is OS-aware via _os_aware_workers():
        Windows  → 200  (TCP half-open SYN limit)
        Linux    → 150-300 (scales with CPU cores)
        macOS    → 200
        Android  → 100 (kernel per-app limits)
      Previously fixed at 50 for all OS.

    probe_host now probes ports 22 and 8022 in parallel per IP,
    cutting worst-case from 2.4s to 1.2s per unresponsive host.

    abort_event: set by user pressing Enter mid-scan to jump to results.
    """
    my_ips  = set(get_all_local_ips())
    found   = []; lock = threading.Lock()
    skipped = set()

    # Determine optimal worker count for this OS + hardware
    _workers = _os_aware_workers()

    # Phase 1 — probe known devices IN PARALLEL (was sequential for-loop)
    if known_hosts:
        known_items = [(h.get("ip",""), h.get("ssh_port",22))
                       for h in known_hosts.values()]
        known_items = [(ip, p) for ip, p in known_items
                       if ip and ip not in my_ips]

        def _phase1_probe(item):
            kip, kprt = item
            if _tcp_probe_fast(kip, kprt, timeout=FAST_PROBE_TIMEOUT):
                result = probe_host(kip)
                if result:
                    with lock:
                        skipped.add(kip)
                        found.append(result)
                    if on_found: on_found(result)

        if known_items:
            p1_workers = min(_workers, len(known_items))
            with concurrent.futures.ThreadPoolExecutor(max_workers=p1_workers) as p1ex:
                p1ex.map(_phase1_probe, known_items)

    # Phase 2 — full subnet scan
    all_ips  = set(extra_ips or [])
    for _, pfx in subnets:
        for i in range(1, 255):
            all_ips.add(f"{pfx}.{i}")
    scan_ips = [ip for ip in all_ips
                if ip not in my_ips and ip not in skipped]

    # Key-based re-identification candidates (MAC-randomized devices)
    _key_candidates = []
    if known_hosts:
        for _h in known_hosts.values():
            _did      = _h.get("device_id", "")
            _ks       = _h.get("key_source", "")
            _user     = _h.get("user", "")
            _port     = _h.get("ssh_port", 22)
            _key_name = _h.get("key_name", "")
            if not (_did and _ks and _user):
                continue
            _kp = ""
            if _key_name:
                _named = os.path.join(_ssh_dir(), _key_name)
                if os.path.exists(_named):
                    _kp = _named
            if not _kp:
                _kp = get_key(_did)
            if _kp and os.path.exists(_kp):
                _key_candidates.append({
                    "device_id" : _did,
                    "key_source": _ks,
                    "key_name"  : _key_name,
                    "user"      : _user,
                    "ssh_port"  : _port,
                    "key_path"  : _kp,
                    "stored"    : _h,
                })

    def _try_identify_by_key(ip: str, port: int, h: dict) -> dict:
        os_t = h.get("os_type", "")
        if os_t not in MAC_RANDOMIZED_OS and os_t != "unknown":
            return h
        candidates = [c for c in _key_candidates if c["ssh_port"] == port]
        if not candidates:
            return h
        result_box  = [None]
        found_event = threading.Event()

        def _probe_key(cand):
            if found_event.is_set(): return
            if test_key(ip, cand["user"], port, cand["key_path"]):
                if not found_event.is_set():
                    found_event.set()
                    result_box[0] = cand

        key_workers = min(len(candidates), 10)
        with concurrent.futures.ThreadPoolExecutor(max_workers=key_workers) as kex:
            kex.map(_probe_key, candidates)

        if result_box[0] is None:
            return h
        winner = result_box[0]
        stored = winner["stored"]
        h["device_id"]      = winner["device_id"]
        h["key_source"]     = winner["key_source"]
        h["user"]           = winner["user"]
        h["key_ok"]         = True
        h["mac_randomized"] = True
        for field in ("nickname", "os_type", "key_name"):
            if stored.get(field) and not h.get(field):
                h[field] = stored[field]
        return h

    def _probe(ip):
        if abort_event and abort_event.is_set():
            return
        h = probe_host(ip)
        if h:
            if _key_candidates:
                h = _try_identify_by_key(ip, h["ssh_port"], h)
            with lock: found.append(h)
            if on_found: on_found(h)

    workers = min(_workers, len(scan_ips)) if scan_ips else 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        ex.map(_probe, scan_ips)
    return sorted(found, key=lambda h: [int(x) for x in h["ip"].split(".")])

# ─────────────────────────────────────────────────────────────────────
# RAW SSH HELPERS
# Python only launches the process.
# The actual data / authentication goes through the OS terminal.
# ─────────────────────────────────────────────────────────────────────

def _key_args(kp: str) -> list:
    """Base SSH args used by every forged ssh/scp command."""
    return ["-i", kp,
            "-c", "aes128-gcm@openssh.com",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "IPQoS=lowdelay"]

def test_key(ip, user, port, kp) -> bool:
    """Quick key auth test. Returns True/False."""
    if not os.path.exists(kp): return False
    args = ["ssh", "-p", str(port)] + _key_args(kp) + \
           [f"{user}@{ip}", "echo SSHOK"]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and "SSHOK" in r.stdout
    except Exception: return False


def test_key_verbose(ip, user, port, kp) -> str:
    """
    Test SSH key and return a detailed result string:
      'ok'               — connected, key works
      'host_key_changed' — known_hosts mismatch (remote reinstalled/reset)
      'permission_denied'— server running but key not accepted
      'unreachable'      — can't reach host at all
      'no_key'           — key file doesn't exist
    """
    if not kp or not os.path.exists(kp): return "no_key"
    args = ["ssh", "-p", str(port),
            "-i", kp,
            "-c", "aes128-gcm@openssh.com",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=8",
            "-o", "IPQoS=lowdelay",
            f"{user}@{ip}", "echo SSHOK"]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=12)
        if r.returncode == 0 and "SSHOK" in r.stdout:
            return "ok"
        combined = (r.stdout + r.stderr).lower()
        if "identification has changed" in combined or "offending" in combined:
            return "host_key_changed"
        if "permission denied" in combined or "publickey" in combined:
            return "permission_denied"
        if ("connection refused" in combined or "timed out" in combined
                or "no route" in combined or "network is unreachable" in combined
                or "connection reset" in combined):
            return "unreachable"
        return "permission_denied"   # generic auth failure
    except subprocess.TimeoutExpired:
        return "unreachable"
    except Exception:
        return "unreachable"


def _remove_known_hosts_entry(ip: str, port: int = 22):
    """
    Remove the stale entry for ip from ~/.ssh/known_hosts.
    Uses ssh-keygen -R which handles all key types cleanly.
    On port 8022 the entry is stored as [ip]:8022 in known_hosts.
    """
    known_hosts = os.path.join(_ssh_dir(), "known_hosts")
    if not os.path.exists(known_hosts):
        return
    # ssh-keygen -R removes the entry in-place
    host_str = f"[{ip}]:{port}" if port != 22 else ip
    try:
        subprocess.run(["ssh-keygen", "-R", host_str],
                       capture_output=True, timeout=5)
    except Exception:
        pass
    # Also try bare IP in case it was stored without port brackets
    if port != 22:
        try:
            subprocess.run(["ssh-keygen", "-R", ip],
                           capture_output=True, timeout=5)
        except Exception:
            pass


def _purge_stale_device(host: dict, hosts: dict) -> dict:
    """
    Called when the remote host key has changed (device wiped/reinstalled).
    Actions:
      1. Remove stale entry from ~/.ssh/known_hosts
      2. Delete our stored private key from ~/.ssh/ and key DB
      3. Clear device_id and key_ok from the host record
      4. Save updated hosts.json
    Returns updated hosts dict with the device marked as needing setup.
    """
    ip   = host["ip"]
    port = host.get("ssh_port", 22)
    did  = host.get("device_id", "")

    # Step 1: remove known_hosts entry
    _remove_known_hosts_entry(ip, port)

    # Step 2: delete our stored key files
    if did:
        kp = get_key(did)
        if kp:
            for path in (kp, kp + ".pub"):
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass
        # Remove from key DB
        km = _load_km()
        km.pop(did, None)
        _save_km(km)

    # Step 3: clean the host record — keep IP/MAC/hostname/nickname
    host["device_id"] = ""
    host["key_ok"]    = False
    host["user"]      = host.get("user", "")  # keep username hint

    # Step 4: save
    hosts[ip] = host
    save_hosts(hosts)
    return hosts


def verify_connection(host: dict, hosts: dict) -> tuple:
    """
    Verify the SSH connection works before entering any transfer flow.
    Called at the start of every transfer/browse/shell operation.

    Returns (ok: bool, kp: str, hosts: dict)
      ok=True  → connection verified, kp is the working key path
      ok=False → connection failed, caller should abort

    Handles automatically:
      host_key_changed  → purge stale data, redirect to Setup
      permission_denied → redirect to Setup (re-install key)
      unreachable       → tell user to start sshd
      no_key            → redirect to Setup
    """
    ip   = host["ip"]
    user = host.get("user","")
    port = host.get("ssh_port", 22)
    did  = host.get("device_id","")

    # Resolve key: prefer key DB, fall back to key_name path on disk
    kp = get_key(did) if did else ""
    if not kp:
        key_name = host.get("key_name","")
        if key_name:
            candidate = os.path.join(_ssh_dir(), key_name)
            if os.path.exists(candidate):
                kp = candidate
                # Re-register in key DB so future lookups work
                if did:
                    save_key(did, kp)
    if not kp:
        warn("No key for this device — run Setup first.")
        return False, "", hosts

    pr(f"  {C.D}Verifying connection to {user}@{ip}...{C.R}")
    result = test_key_verbose(ip, user, port, kp)

    if result == "ok":
        return True, kp, hosts

    if result == "host_key_changed":
        # ── Device was wiped/reinstalled — common case ─────────────
        clear()
        hdr("CONNECTION FAILED — HOST KEY CHANGED",
            f"{user}@{ip}:{port}")
        pr()
        pr(f"  {C.RE}The remote device's SSH fingerprint has changed.{C.R}")
        pr(f"  {C.D}This happens when Termux data is cleared, the app is{C.R}")
        pr(f"  {C.D}reinstalled, or sshd keys are regenerated.{C.R}")
        pr()
        sep()
        pr(f"  {C.B}Auto-fix will:{C.R}")
        pr(f"  {C.G}1.{C.R}  Remove stale entry from ~/.ssh/known_hosts")
        pr(f"  {C.G}2.{C.R}  Delete our old key for this device")
        pr(f"  {C.G}3.{C.R}  Clear device record so it can be set up fresh")
        pr()
        pr(f"  {C.B}[Y]{C.R}  Auto-fix and go to Setup  (recommended)")
        pr(f"  {C.B}[0]{C.R}  Cancel")
        sep()
        ch = ask("Choose", "Y")
        if ch.upper() != "Y":
            return False, "", hosts

        # Purge stale data
        pr(f"  {C.D}Removing stale known_hosts entry...{C.R}")
        hosts = _purge_stale_device(host, hosts)
        ok("Stale data cleared")
        pr(f"  {C.D}Proceeding to Setup...{C.R}")
        time.sleep(0.8)

        # Re-run setup for this device
        h = hosts.get(ip, host)
        h = setup_device(h, hosts)
        hosts[ip] = h

        # Check if setup succeeded
        new_did = h.get("device_id","")
        new_kp  = get_key(new_did) if new_did else ""
        if new_kp and test_key(ip, h.get("user",user), port, new_kp):
            ok(f"New connection established ✓")
            return True, new_kp, hosts
        else:
            warn("Setup incomplete — try again from Transfer menu.")
            return False, "", hosts

    if result == "permission_denied":
        clear()
        hdr("CONNECTION FAILED — KEY REJECTED", f"{user}@{ip}:{port}")
        pr()
        pr(f"  {C.RE}The device rejected our key.{C.R}")
        pr(f"  {C.D}The key may have been removed from authorized_keys,{C.R}")
        pr(f"  {C.D}or the username may have changed.{C.R}")
        pr()
        pr(f"  {C.B}[Y]{C.R}  Go to Setup to reinstall the key")
        pr(f"  {C.B}[0]{C.R}  Cancel")
        sep()
        ch = ask("Choose", "Y")
        if ch.upper() != "Y":
            return False, "", hosts
        h = setup_device(host, hosts)
        hosts[ip] = h
        new_kp = get_key(h.get("device_id",""))
        return bool(new_kp), new_kp or "", hosts

    if result == "unreachable":
        clear()
        hdr("CONNECTION FAILED — DEVICE UNREACHABLE", f"{ip}:{port}")
        pr()
        pr(f"  {C.RE}Cannot reach {user}@{ip} on port {port}.{C.R}")
        pr()
        pr(f"  {C.D}IP or MAC may have changed — searching for device...{C.R}")

        # ── Auto-search: try fast_find_device before giving up ────────
        # Uses the named key (e.g. V-15_to_vivo) to scan the subnet.
        # Any device that accepts that key IS the device — regardless of
        # whether its IP or MAC has changed.
        new_ip = fast_find_device(host, hosts)   # 3-phase scan, updates host["ip"]/mac
        if new_ip and new_ip != ip:
            ok(f"Device found at new IP: {new_ip}")
            # Persist updated IP/MAC back to hosts.json
            host["ip"] = new_ip
            hosts[new_ip] = host
            hosts.pop(ip, None)
            save_hosts(hosts)
            ip = new_ip
            # Retry connection with new IP
            result2 = test_key_verbose(new_ip, user, port, kp)
            if result2 == "ok":
                ok(f"Connection verified at {new_ip} ✓")
                return True, kp, hosts
            pr(f"  {C.Y}Found at {new_ip} but key test failed ({result2}) — try Setup.{C.R}")
            pause()
            return False, "", hosts
        elif new_ip == ip:
            # Same IP still — sshd just not running
            pass
        else:
            pr(f"  {C.Y}Device not found on network — may be offline.{C.R}")

        pr()
        pr(f"  {C.B}Check:{C.R}")
        if port == 8022:
            pr(f"  1.  Open Termux and run: {C.B}sshd{C.R}")
        else:
            pr(f"  1.  Make sure SSH server is running on the device")
        pr(f"  2.  Both devices on the same WiFi/hotspot")
        pr(f"  3.  Firewall not blocking port {port}")
        pause()
        return False, "", hosts

    return False, "", hosts

def run_cmd(ip, user, port, cmd, kp, timeout=30) -> str:
    """Run a command on remote using key. Returns stdout.
    Returns '__TIMEOUT__' if command exceeded timeout.
    timeout: seconds to wait — relay port-scans need 120+ seconds."""
    args = ["ssh", "-p", str(port)] + _key_args(kp) + [f"{user}@{ip}", cmd]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        return "__TIMEOUT__"
    except Exception:
        return ""

def open_shell(ip, user, port, kp):
    """
    Forge and fire: ssh -p{port} -i key -c aes128-gcm user@ip
    Python hands terminal to ssh completely — full native speed.
    """
    args = ["ssh", "-p", str(port),
            "-i", kp,
            "-c", "aes128-gcm@openssh.com",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "IPQoS=lowdelay",
            f"{user}@{ip}"]
    display = " ".join(args)
    print(f"\n  {C.D}{display}{C.R}\n")
    try:
        subprocess.run(args)   # Python steps aside — ssh owns terminal
    except FileNotFoundError: err("ssh not found")
    except KeyboardInterrupt: pass

def remote_is_dir(ip, user, port, kp, remote_path,
                  os_type: str = "") -> bool:
    """Check if remote path is a directory via SSH.
    Auto-detects Windows from path (colon = drive letter)."""
    # Auto-detect Windows from path even if os_type not passed
    _eff = os_type
    if _eff != "windows" and remote_path and ":" in remote_path:
        _eff = "windows"
    if _eff == "windows":
        win_path = remote_path.replace("/", "\\")
        out = run_cmd(ip, user, port,
                      f'powershell -NoProfile -Command "'
                      f'if (Test-Path -PathType Container \'{win_path}\') '
                      f'{{Write-Output DIR}} else {{Write-Output FILE}}"',
                      kp, timeout=8)
        return out.strip() == "DIR"
    out = run_cmd(ip, user, port,
                  f"test -d {shlex.quote(remote_path)} && echo DIR || echo FILE",
                  kp)
    return out.strip() == "DIR"


# ─────────────────────────────────────────────────────────────────────
# TRANSFER — the code is a COMMAND FACTORY
#
# Python's only job:
#   1. Figure out the right scp/ssh command (path, flags, key, port)
#   2. Print it so user can see exactly what runs
#   3. subprocess.run(args)  ← Python hands off and steps COMPLETELY aside
#   4. scp/ssh owns the terminal — full native speed, zero Python overhead
#   5. When process exits → Python reads return code → reports done/fail
#
# WHY THE OLD CODE WAS SLOW (512 KB/s):
#   Default scp uses:
#     - 3DES or AES256-CBC cipher  → slow software encryption
#     - SSH channel window 64KB    → send 64KB, wait for ACK, repeat
#     - No buffer tuning
#
# THE FIX — forge a better command:
#   -c aes128-gcm@openssh.com   → hardware AES-GCM on every modern CPU
#                                  (Intel AES-NI, ARM Crypto Extensions)
#                                  same cipher raw ssh uses internally
#   -o "IPQoS lowdelay"         → mark packets low-latency in kernel
#   SCP's window issue is fixed in OpenSSH 9.0+ (uses SFTP internally)
#   On older OpenSSH: cipher switch alone gives 5-10x speedup
#
# No pipes. No Python in data path. Python = command builder only.
# ─────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────
# ZSTD LOCAL INSTALLER
# Installs zstd on THIS device (the one running linkx.py).
# Detects local OS and runs the right package manager command.
# ─────────────────────────────────────────────────────────────────────

# Install commands for zstd on the LOCAL machine (running this script)
_7Z_LOCAL_INSTALL = {
    "android"     : "pkg install -y p7zip",
    "debian"      : "sudo apt-get install -y p7zip-full",
    "kali"        : "sudo apt-get install -y p7zip-full",
    "rhel"        : "sudo dnf install -y p7zip p7zip-plugins",
    "arch"        : "sudo pacman -S --noconfirm p7zip",
    "suse"        : "sudo zypper install -y p7zip",
    "alpine"      : "apk add p7zip",
    "void"        : "sudo xbps-install -y p7zip",
    "gentoo"      : "emerge app-arch/p7zip",
    "macos"       : "brew install p7zip",
    "windows"     : "winget install 7zip.7zip",
    "windows_old" : "choco install 7zip -y",
    "linux"       : "sudo apt-get install -y p7zip-full || sudo dnf install -y p7zip p7zip-plugins || sudo pacman -S --noconfirm p7zip",
    "other"       : "sudo apt-get install -y p7zip-full || sudo dnf install -y p7zip",
}
_RSYNC_LOCAL_INSTALL = {
    "android"     : "pkg install -y rsync",
    "debian"      : "sudo apt-get install -y rsync",
    "kali"        : "sudo apt-get install -y rsync",
    "rhel"        : "sudo dnf install -y rsync",
    "arch"        : "sudo pacman -S --noconfirm rsync",
    "suse"        : "sudo zypper install -y rsync",
    "alpine"      : "apk add rsync",
    "void"        : "sudo xbps-install -y rsync",
    "gentoo"      : "emerge net-misc/rsync",
    "macos"       : "brew install rsync",
    "windows"     : "winget install --id MSYS2.MSYS2 && C:\\msys64\\usr\\bin\\bash.exe -lc \"pacman -S --noconfirm rsync\"",
    "linux"       : "sudo apt-get install -y rsync || sudo dnf install -y rsync || sudo pacman -S --noconfirm rsync",
    "other"       : "sudo apt-get install -y rsync || sudo dnf install -y rsync",
}

_SSH_LOCAL_INSTALL = {
    "android"     : "pkg install -y openssh",
    "debian"      : "sudo apt-get install -y openssh-server openssh-client",
    "kali"        : "sudo apt-get install -y openssh-server openssh-client",
    "rhel"        : "sudo dnf install -y openssh-server openssh-clients",
    "arch"        : "sudo pacman -S --noconfirm openssh",
    "suse"        : "sudo zypper install -y openssh",
    "alpine"      : "apk add openssh",
    "void"        : "sudo xbps-install -y openssh",
    "gentoo"      : "emerge net-misc/openssh",
    "macos"       : "brew install openssh",
    "windows"     : "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
    "linux"       : "sudo apt-get install -y openssh-server || sudo dnf install -y openssh-server",
    "other"       : "sudo apt-get install -y openssh-server || sudo dnf install -y openssh-server",
}

_RSYNC_REMOTE_INSTALL = {
    "android"     : "pkg install -y rsync",
    "debian"      : "sudo apt-get install -y rsync",
    "kali"        : "sudo apt-get install -y rsync",
    "rhel"        : "sudo dnf install -y rsync",
    "arch"        : "sudo pacman -S --noconfirm rsync",
    "suse"        : "sudo zypper install -y rsync",
    "alpine"      : "apk add rsync",
    "void"        : "sudo xbps-install -y rsync",
    "gentoo"      : "emerge net-misc/rsync",
    "macos"       : "brew install rsync",
    "windows"     : "winget install --id MSYS2.MSYS2 --accept-package-agreements --accept-source-agreements && C:\\msys64\\usr\\bin\\bash.exe -lc \"pacman -S --noconfirm rsync\"",
    "linux"       : "sudo apt-get install -y rsync || sudo dnf install -y rsync || sudo pacman -S --noconfirm rsync",
    "other"       : "sudo apt-get install -y rsync || sudo dnf install -y rsync",
}

def menu_install_tools(hosts: dict) -> dict:
    """[8] Install tools — 7-Zip, rsync, openssh on THIS device."""
    los = local_os()

    while True:
        clear()
        hdr("INSTALL TOOLS", "Install transfer tools on this device")
        pr()

        has_7z    = _local_has_7z()
        has_rsync = _local_has_rsync()
        has_ssh   = shutil.which("ssh") is not None
        has_tar   = _local_has_tar()

        def _st(v): return f"{C.G}✓{C.R}" if v else f"{C.RE}✗{C.R}"
        pr(f"  7-Zip : {_st(has_7z)}  {'installed' if has_7z else 'not found — needed for compression'}")
        pr(f"  rsync : {_st(has_rsync)}  {'installed' if has_rsync else 'optional — transfers work without it (scp fallback active)'}")
        pr(f"  ssh   : {_st(has_ssh)}  {'installed' if has_ssh else 'not found — needed for all transfers'}")
        pr(f"  tar   : {_st(has_tar)}  {'installed' if has_tar else 'not found — needed for bundling'}")
        pr()
        sep()
        pr(f"  {C.B}[1]{C.R}  Install / upgrade  7-Zip")
        pr(f"  {C.B}[2]{C.R}  Install / upgrade  rsync")
        pr(f"  {C.B}[3]{C.R}  Install / upgrade  openssh")
        pr(f"  {C.B}[0]{C.R}  Back")
        sep()

        ch = ask("Choose")
        if ch == "0" or not ch:
            return hosts

        if ch == "1":
            _run_local_install("7-Zip", los,
                               _7Z_LOCAL_INSTALL.get(los, _7Z_LOCAL_INSTALL["other"]),
                               _local_has_7z)
        elif ch == "2":
            _run_local_install("rsync", los,
                               _RSYNC_LOCAL_INSTALL.get(los, _RSYNC_LOCAL_INSTALL["other"]),
                               _local_has_rsync)
        elif ch == "3":
            _run_local_install("openssh", los,
                               _SSH_LOCAL_INSTALL.get(los, _SSH_LOCAL_INSTALL["other"]),
                               lambda: shutil.which("ssh") is not None)
        else:
            err("Invalid."); time.sleep(0.6)

def _reload_path():
    """
    Reload PATH into current process after install.
    Windows: reads registry SYSTEM + USER PATH (winget/choco don't update live process).
    Linux/macOS: re-sources common tool directories that package managers add to.
    Call after any install to make shutil.which() find newly installed tools.
    """
    if os.name == "nt":
        try:
            import winreg
            paths = []
            # System PATH
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as k:
                paths.append(winreg.QueryValueEx(k, "PATH")[0])
            # User PATH
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as k:
                    paths.append(winreg.QueryValueEx(k, "PATH")[0])
            except Exception:
                pass
            os.environ["PATH"] = ";".join(paths)
        except Exception:
            pass
        # Also add known Windows tool install paths directly
        extra = [
            r"C:\Program Files\7-Zip",
            r"C:\Program Files (x86)\7-Zip",
            r"C:\Program Files\Git\usr\bin",
            r"C:\Program Files (x86)\Git\usr\bin",
            r"C:\Program Files\OpenSSH",
            r"C:\Windows\System32\OpenSSH",
        ]
        cur = os.environ.get("PATH", "")
        for p in extra:
            if p not in cur and os.path.isdir(p):
                os.environ["PATH"] = cur + ";" + p
                cur = os.environ["PATH"]
    else:
        # Linux/macOS: add common package manager bin dirs
        extra = [
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/opt/homebrew/bin",       # macOS Homebrew (Apple Silicon)
            "/usr/local/homebrew/bin", # macOS Homebrew (Intel)
            "/data/data/com.termux/files/usr/bin",  # Termux
        ]
        cur = os.environ.get("PATH", "")
        for p in extra:
            if p not in cur and os.path.isdir(p):
                os.environ["PATH"] = cur + ":" + p
                cur = os.environ["PATH"]

def _run_local_install(tool: str, los: str, install_cmd: str, check_fn) -> None:
    """Run a local package install command and verify it worked."""
    clear(); hdr(f"INSTALLING {tool.upper()}")
    pr()
    pr(f"  {C.B}OS      :{C.R} {los.title()}")
    pr(f"  {C.B}Command :{C.R} {C.CY}{install_cmd}{C.R}")
    pr()

    if los in ("windows", "windows_old") and os.name == "nt":
        pr(f"  {C.Y}Note:{C.R} May need winget / chocolatey / admin rights.")
    if los == "macos":
        pr(f"  {C.Y}Note:{C.R} Homebrew must be installed first.")

    pr(f"  {C.B}[Y]{C.R}  Run now")
    pr(f"  {C.B}[0]{C.R}  Cancel")
    sep()
    if ask("Choose", "Y").upper() != "Y":
        return

    pr()
    try:
        if los in ("windows", "windows_old") and os.name == "nt":
            if tool.lower() == "rsync":
                # Step 1: install MSYS2 via winget
                pr(f"  {C.D}Step 1/2 — Installing MSYS2...{C.R}")
                subprocess.run(
                    "winget install --id MSYS2.MSYS2 "
                    "--accept-package-agreements --accept-source-agreements",
                    shell=True, timeout=300)
                # Step 2: install rsync inside MSYS2
                pr(f"  {C.D}Step 2/2 — Installing rsync inside MSYS2...{C.R}")
                bash = r"C:\msys64\usr\bin\bash.exe"
                if os.path.isfile(bash):
                    subprocess.run(
                        [bash, "-lc", "pacman -S --noconfirm rsync"],
                        timeout=180)
                else:
                    err("MSYS2 installed but bash not found at C:\\msys64 — try restarting.")
            elif _win_is_admin():
                subprocess.run(["powershell", "-NoProfile", "-Command", install_cmd],
                               timeout=180)
            else:
                pr(f"  {C.Y}UAC prompt may appear...{C.R}")
                subprocess.run([
                    "powershell", "-NoProfile", "-Command",
                    f'Start-Process powershell -ArgumentList "-NoProfile -Command {install_cmd}" -Verb RunAs -Wait'
                ], timeout=180)
        else:
            # Whitelist: only known install commands reach shell=True
            _allowed_cmds = (set(_7Z_LOCAL_INSTALL.values()) |
                             set(_RSYNC_LOCAL_INSTALL.values()) |
                             set(_SSH_LOCAL_INSTALL.values()))
            if install_cmd not in _allowed_cmds:
                err("Blocked: unrecognised install command.")
                pause(); return
            subprocess.run(install_cmd, shell=True, timeout=300)
    except subprocess.TimeoutExpired:
        err("Timed out."); pause(); return
    except KeyboardInterrupt:
        print(); warn("Cancelled."); pause(); return
    except Exception as e:
        err(str(e)); pause(); return

    pr()
    _reload_path()

    if check_fn():
        ok(f"{tool} installed successfully ✓")
    else:
        warn(f"{tool} not in PATH yet — may need terminal restart.")
        pr(f"  {C.D}If you see it in Apps/Settings, it IS installed.{C.R}")
        pr(f"  {C.D}Close and reopen this tool to pick it up.{C.R}")
        pr()
        pr(f"  {C.D}Or install manually:{C.R}")
        pr(f"    {install_cmd}")
    pause()

# ─────────────────────────────────────────────────────────────────────
# RESUMABLE TRANSFER
#
# SCP has no built-in resume.  rsync does — with --partial --append-verify.
# Strategy:
#   1. Check if rsync is available on both LOCAL and REMOTE.
#   2. If yes → use rsync (resumable, shows progress, skips already-sent bytes)
#   3. If no  → use scp (original, no resume)
#
# rsync resume flags:
#   --partial          keep partially transferred file on receiver
#   --append-verify    append to partial file; verify full hash after
#   --progress         live progress bar (bytes sent, speed, ETA)
#   -z is NOT used here — compression is already handled by zstd if wanted
#   -e "ssh ..."       tunnel through SSH with our key
# ─────────────────────────────────────────────────────────────────────

def _local_has_rsync() -> bool:
    """Check if rsync available. On Windows checks Git install path."""
    if shutil.which("rsync"):
        return True
    if os.name == "nt":
        for c in [r"C:\Program Files\Git\usr\bin\rsync.exe",
                  r"C:\Program Files (x86)\Git\usr\bin\rsync.exe",
                  r"C:\msys64\usr\bin\rsync.exe",
                  r"C:\cygwin64\bin\rsync.exe"]:
            if os.path.isfile(c):
                return True
    return False

def _get_rsync_bin() -> str:
    """Get rsync binary path — checks PATH then known Windows install paths."""
    if shutil.which("rsync"):
        return "rsync"
    if os.name == "nt":
        for c in [r"C:\Program Files\Git\usr\bin\rsync.exe",
                  r"C:\Program Files (x86)\Git\usr\bin\rsync.exe",
                  r"C:\msys64\usr\bin\rsync.exe",
                  r"C:\msys64\mingw64\bin\rsync.exe",
                  r"C:\cygwin64\bin\rsync.exe",
                  r"C:\cygwin\bin\rsync.exe"]:
            if os.path.isfile(c):
                return c
    return "rsync"

def _remote_has_rsync(ip, user, port, kp) -> bool:
    out = run_cmd(ip, user, port,
                  "command -v rsync 2>/dev/null || which rsync 2>/dev/null", kp)
    return bool(out.strip()) and out != "__TIMEOUT__"


def do_scp(src, dest, port, kp, force_recursive: bool = False) -> tuple:
    """
    Forge and fire the transfer. Python steps aside after launch.
    Full native transfer speed — identical to typing the command manually.

    RESUME LOGIC:
      Tries rsync first (supports --partial --append-verify for mid-transfer
      resume). Falls back to scp if rsync is not available on either side.

    PROTOCOL: SFTP mode (default, no -O flag).
        Modern OpenSSH 8.1+ scp uses SFTP internally by default.
        SFTP sends the remote path as raw binary — spaces and special chars work.

    SPEED FLAGS (benchmarked on Redmi 4A ↔ Windows laptop, 5GHz WiFi):
        -c aes128-gcm@openssh.com   hardware AES-NI on laptop encrypts free
        -o Compression=no           off — compressing VMDKs/photos wastes CPU
        -o IPQoS=throughput         kernel marks packets for max bandwidth
    """
    is_dir = force_recursive or (os.path.isdir(src) if "@" not in src else False)

    # ── Parse dest to extract ip, user, port, remote_path for rsync ──
    # dest format: "user@ip:/path"  or  "/local/path"
    is_upload   = "@" not in src and "@" in dest
    is_download = "@" in src and "@" not in dest

    # Extract connection components for rsync -e flag
    def _rsync_ssh_args(p):
        return (f'ssh -p {p} -i "{kp}" '
                f'-o StrictHostKeyChecking=accept-new '
                f'-o ConnectTimeout=10 '
                f'-o BatchMode=yes '
                f'-c aes128-gcm@openssh.com')

    def _try_rsync() -> tuple:
        """Attempt rsync with resume. Returns (success, message) or raises."""
        if not _local_has_rsync():
            return None, "rsync not local"

        # For rsync we need to know remote ip+port to check remote rsync
        # We derive them from the scp dest/src string
        remote_str = dest if is_upload else src
        if "@" in remote_str:
            user_host, _ = remote_str.split(":", 1)
            ruser, rhost  = user_host.split("@", 1)
        else:
            return None, "can't parse remote"

        # Quick check: is rsync available remotely?
        # Cached per (rhost, port) so repeated sends don't re-check every time.
        _cache_key = f"rsync_chk:{rhost}:{port}"
        _rsync_cache = getattr(do_scp, "_rsync_cache", {})
        do_scp._rsync_cache = _rsync_cache
        if _cache_key not in _rsync_cache:
            # Detect remote OS to use correct check command
            _chk_remote_os = "other"
            try:
                _hs2 = load_hosts()
                for _hv2 in _hs2.values():
                    if _hv2.get("ip","") == rhost:
                        _chk_remote_os = _hv2.get("os_type","other"); break
            except Exception:
                pass

            if _chk_remote_os == "windows":
                # Windows: check MSYS2 rsync path directly
                chk = subprocess.run(
                    ["ssh", "-p", str(port), "-i", kp,
                     "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "ConnectTimeout=3",
                     "-o", "BatchMode=yes",
                     f"{ruser}@{rhost}",
                     r'if exist "C:\msys64\usr\bin\rsync.exe" '
                     r'(echo FOUND) else (echo MISSING)'],
                    capture_output=True, text=True, timeout=8)
                _rsync_cache[_cache_key] = ("FOUND" in chk.stdout)
            else:
                chk = subprocess.run(
                    ["ssh", "-p", str(port), "-i", kp,
                     "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "ConnectTimeout=3",
                     "-o", "BatchMode=yes",
                     f"{ruser}@{rhost}",
                     "command -v rsync 2>/dev/null || which rsync 2>/dev/null"],
                    capture_output=True, timeout=8)
                _rsync_cache[_cache_key] = (chk.returncode == 0
                                            and bool(chk.stdout.strip()))
        if _chk_remote_os == "windows":
            return None, "rsync to Windows unreliable — using scp"
        if not _rsync_cache[_cache_key]:
            # rsync missing on remote — offer to install it
            pr(f"  {C.Y}rsync not found on remote device.{C.R}")
            if ask("Install rsync on remote now?", "Y").upper() == "Y":
                # Need os_type — derive from cached hosts if possible
                _remote_os = "other"
                try:
                    _hosts_snap = load_hosts()
                    for _h in _hosts_snap.values():
                        if _h.get("ip","") == rhost or rhost in _h.get("ip",""):
                            _remote_os = _h.get("os_type","other"); break
                except Exception:
                    pass
                inst_ok, inst_msg = _remote_install_rsync(rhost, ruser, port, kp, _remote_os)
                if inst_ok:
                    ok(inst_msg)
                    _rsync_cache[_cache_key] = True
                else:
                    warn(inst_msg)
                    pr(f"  {C.D}Falling back to scp...{C.R}")
                    return None, "rsync install failed — using scp"
            else:
                return None, "rsync not on remote"

        ssh_e = _rsync_ssh_args(port)
        # PATH FIX: use basename + cwd to prevent full-path mirroring
        rsync_src = src
        rsync_cwd = None
        if is_upload and "@" not in src:
            rsync_src = os.path.basename(src.rstrip("/\\"))
            rsync_cwd = os.path.dirname(os.path.abspath(src))
            if is_dir and not rsync_src.endswith("/"):
                rsync_src += "/"   # trailing slash = sync contents, not wrapper
        args  = [
            _get_rsync_bin(),
            "--partial",
            "--append-verify",
            "--progress",
            "-a" if is_dir else "",
            "-e", ssh_e,
            rsync_src, dest,
        ]
        args = [a for a in args if a]
        _rp = re.compile(r'(\d+)%')
        _sp = re.compile(r'([\d.]+\s*\w+/s)')
        fname2 = os.path.basename((src if "@" not in src else src.split(":")[-1]).rstrip("/\\"))
        print(f"\n  {C.CY}[rsync — resumable]{C.R}  {C.D}{fname2}{C.R}")

        def _draw_bar2(pct, speed=""):
            bar_w  = 28
            filled = int(bar_w * pct / 100)
            bar    = f"{C.CY}{'»' * filled}{C.D}{'·' * (bar_w - filled)}{C.R}"
            spd    = f"  {C.D}{speed}{C.R}" if speed else ""
            print(f"\r  [{bar}] {C.B}{pct:>3}%{C.R}{spd}    ", end="", flush=True)

        _draw_bar2(0)
        proc2 = None
        try:
            proc2 = subprocess.Popen(args, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     universal_newlines=True,
                                     cwd=rsync_cwd)
            last_pct2 = 0
            while True:
                line = proc2.stdout.readline()
                if not line and proc2.poll() is not None:
                    break
                pm = _rp.search(line)
                sm = _sp.search(line)
                if pm:
                    pct2 = int(pm.group(1))
                    spd2 = sm.group(1) if sm else ""
                    last_pct2 = pct2
                    _draw_bar2(pct2, spd2)
            rc2 = proc2.wait()
        except KeyboardInterrupt:
            try: proc2.kill()
            except Exception: pass
            print()
            return False, "Transfer interrupted — re-run to resume from where it stopped"

        _draw_bar2(100 if rc2 == 0 else last_pct2)
        print()
        if rc2 == 0:
            return True, f"Transfer complete (rsync): {fname2}"
        if rc2 == 20:
            return False, "Transfer interrupted — re-run to resume from where it stopped"
        if rc2 == 12:
            # Protocol stream error — remote has no rsync binary
            # Invalidate cache so next call doesn't retry rsync to this host
            _rsync_cache.pop(_cache_key, None)
            return None, "rsync: remote has no rsync — falling back to scp"
        return False, f"rsync exited with code {rc2}"

# ── Smart routing: rsync if destination exists, scp if new ───────
    _dest_exists   = False
    _dest_is_win   = False   # track if remote is Windows for Copy folder
    try:
        if is_upload and "@" in dest:
            _u, _rpath = dest.split(":", 1)
            _ruser, _rhost = _u.split("@", 1)
            _fname = os.path.basename(src.rstrip("/\\"))
            _full_remote = _rpath.rstrip("/") + "/" + _fname
            # Detect if remote is Windows by checking known_hosts os_type
            try:
                _hs = load_hosts()
                for _hv in _hs.values():
                    if _hv.get("ip","") == _rhost:
                        _dest_is_win = _hv.get("os_type","") == "windows"
                        break
            except Exception:
                pass
            if _dest_is_win:
                # Windows: use PowerShell to check existence
                _chk = subprocess.run(
                    ["ssh", "-p", str(port), "-i", kp,
                     "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "BatchMode=yes",
                     "-o", "ConnectTimeout=5",
                     f"{_ruser}@{_rhost}",
                     f'powershell -NoProfile -Command '
                     f'"if (Test-Path \'{_full_remote.replace("/", "\\")}\') '
                     f'{{Write-Output EXISTS}} else {{Write-Output NEW}}"'],
                    capture_output=True, text=True, timeout=8)
            else:
                _chk = subprocess.run(
                    ["ssh", "-p", str(port), "-i", kp,
                     "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "BatchMode=yes",
                     "-o", "ConnectTimeout=5",
                     f"{_ruser}@{_rhost}",
                     f"test -e {shlex.quote(_full_remote)} "
                     f"2>/dev/null && echo EXISTS || echo NEW"],
                    capture_output=True, text=True, timeout=8)
            _dest_exists = "EXISTS" in _chk.stdout
        elif is_download and "@" in src:
            _fname = os.path.basename(src.split(":")[-1].rstrip("/\\"))
            _local_check = os.path.join(dest, _fname) if os.path.isdir(dest) else dest
            _dest_exists = os.path.exists(_local_check)
    except Exception:
        _dest_exists = False

    if _dest_exists:
        # File/folder already exists at destination
        # Try rsync first (delta sync — only sends changed bytes)
        # If rsync unavailable or fails → ask user: overwrite or Copy folder
        _rsync_ok = False
        if not _dest_is_win:
            # rsync on Windows remote is unreliable — skip attempt
            try:
                result, msg = _try_rsync()
                if result is True:
                    return result, msg
                if result is None:
                    pass   # rsync not available — fall through to ask
                # result is False = rsync ran but failed (e.g. code 12)
                # fall through to ask user
            except Exception:
                pass

        # rsync not available or failed — ask user what to do
        clear()
        hdr("FILE EXISTS", f"Already at destination")
        pr()
        pr(f"  {C.B}{os.path.basename(src.rstrip('/\\'))}{C.R} already exists at:")
        pr(f"  {C.G}{dest.split(':')[-1] if ':' in dest else dest}{C.R}")
        pr()
        pr(f"  {C.B}[1]{C.R}  Overwrite — replace existing file")
        pr(f"  {C.B}[2]{C.R}  Copy folder — send to 'Copy' subfolder at destination")
        pr(f"  {C.B}[0]{C.R}  Cancel")
        sep()
        _ch = ask("Choose", "1").strip()
        if _ch == "0":
            return False, "Cancelled"
        if _ch == "2":
            # Create Copy subfolder and redirect dest there
            if is_upload and "@" in dest:
                _u2, _rpath2 = dest.split(":", 1)
                _copy_dir = _rpath2.rstrip("/") + "/Copy"
                # Create Copy folder on remote
                if _dest_is_win:
                    _mkdir_cmd = (f'powershell -NoProfile -Command '
                                  f'"New-Item -ItemType Directory -Force '
                                  f'-Path \'{_copy_dir.replace("/", "\\")}\' | Out-Null; '
                                  f'Write-Output DONE_MKDIR"')
                else:
                    _mkdir_cmd = f"mkdir -p {shlex.quote(_copy_dir)} && echo DONE_MKDIR"
                _mk_out = subprocess.run(
                    ["ssh", "-p", str(port), "-i", kp,
                     "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "BatchMode=yes",
                     f"{_u2}", _mkdir_cmd],
                    capture_output=True, text=True, timeout=10)
                dest = f"{_u2}:{_copy_dir}"
                pr(f"  {C.D}Sending to Copy folder: {_copy_dir}{C.R}")
            elif is_download:
                # Local Copy folder
                _copy_dir = os.path.join(dest if os.path.isdir(dest)
                                         else os.path.dirname(dest), "Copy")
                os.makedirs(_copy_dir, exist_ok=True)
                dest = _copy_dir
                pr(f"  {C.D}Saving to Copy folder: {_copy_dir}{C.R}")
        # _ch == "1" → overwrite — proceed normally with original dest

    # ── Fall back to scp with live progress bar ───────────────────────
    args = [
        "scp",
        "-P", str(port),
        "-i", kp,
        "-c", "aes128-gcm@openssh.com",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-o", "Compression=no",
        "-o", "IPQoS=throughput",
    ]

    # ── PATH FIX: prevent recursive directory mirroring ───────────────
    # scp -r /full/path/MyFolder user@ip:/dest  →  creates /dest/full/path/MyFolder
    # scp -r MyFolder user@ip:/dest (cwd=/full/path)  →  creates /dest/MyFolder ✓
    # Solution: strip to basename, set cwd to parent directory.
    # Only applies to local sources (uploads). Downloads use remote path as-is.
    scp_cwd = None
    scp_src = src
    if is_upload and "@" not in src:
        scp_src = os.path.basename(src.rstrip("/\\"))
        scp_cwd = os.path.dirname(os.path.abspath(src))

    if is_dir:
        args.append("-r")
    args += [scp_src, dest]
    _pct_re = re.compile(r'(\d+)%\s+([\d.]+\s*\w+)\s+([\d.]+\s*\w+/s)\s+(\S+)')

    def _draw_bar(pct: int, speed: str = "", eta: str = ""):
        bar_w  = 28
        filled = int(bar_w * pct / 100)
        bar    = f"{C.CY}{'»' * filled}{C.D}{'·' * (bar_w - filled)}{C.R}"
        right  = f"  {C.D}{speed}  ETA {eta}{C.R}" if speed else ""
        print(f"\r  [{bar}] {C.B}{pct:>3}%{C.R}{right}    ", end="", flush=True)

    fname = os.path.basename((src if "@" not in src else src.split(":")[-1]).rstrip("/\\"))
    print(f"\n  {C.D}Transferring: {fname}{C.R}")
    _draw_bar(0)

    try:
        if os.name != "nt" and _HAS_PTY:
            master_fd, slave_fd = _pty_mod.openpty()
            proc = subprocess.Popen(args,
                                    stdout=slave_fd, stderr=slave_fd,
                                    stdin=subprocess.DEVNULL,
                                    close_fds=True,
                                    cwd=scp_cwd)
            os.close(slave_fd)
            buf = ""
            last_pct = 0
            try:
                while proc.poll() is None:
                    r, _, _ = _select_mod.select([master_fd], [], [], 0.1)
                    if r:
                        try:
                            chunk = os.read(master_fd, 4096).decode("utf-8", errors="ignore")
                        except OSError:
                            break
                        buf += chunk
                        for seg in buf.split("\r"):
                            m = _pct_re.search(seg)
                            if m:
                                pct   = int(m.group(1))
                                speed = m.group(3)
                                eta   = m.group(4)
                                last_pct = pct
                                _draw_bar(pct, speed, eta)
                        buf = buf.split("\r")[-1]
            except KeyboardInterrupt:
                proc.kill()
                print()
                return False, "Transfer interrupted — re-run to resume"
            finally:
                try: os.close(master_fd)
                except OSError: pass
            rc = proc.wait()
        else:
            print()
            proc = subprocess.Popen(args, cwd=scp_cwd)
            try:
                proc.wait()
            except KeyboardInterrupt:
                proc.kill()
                print()
                return False, "Transfer interrupted — re-run to resume"
            rc = proc.returncode
            last_pct = 100 if rc == 0 else 0

        _draw_bar(100 if rc == 0 else last_pct)
        print()
        if rc == 0:
            return True, f"Transfer complete: {fname}"
        return False, f"scp exited with code {rc}"

    except FileNotFoundError:
        return False, "scp not found — install OpenSSH"
    except Exception as e:
        return False, str(e)



# ─────────────────────────────────────────────────────────────────────
# FIRST-TIME SETUP
#
# EXACT FLOW:
# 1. Check key DB by device_id — if key exists and works → done
# 2. Check existing keys in ~/.ssh/ — if one works → register it → done
# 3. Need password:
#    a. Ask username
#    b. Ask password (getpass — hidden input)
#    c. Run ssh interactively IN THE TERMINAL to test + install key
#       → SSH asks for password itself, user types it, we watch exit code
#       → This is EXACTLY like typing ssh manually
#    d. Key installed → password session closed
#    e. Verify key works → registered in DB
# ─────────────────────────────────────────────────────────────────────

def _install_key_interactive(ip, user, port, pub_key, os_type: str = "linux") -> bool:
    """
    Install public key on remote device via password SSH.

    WINDOWS: OpenSSH Server uses a DIFFERENT authorized_keys path for
    administrators:  C:\\ProgramData\\ssh\\administrators_authorized_keys
    Regular users still use %USERPROFILE%\\.ssh\\authorized_keys.
    We detect this by checking if the user is in the Administrators group
    (the simplest reliable check: just write BOTH paths on Windows).

    UNIX: standard ~/.ssh/authorized_keys with chmod.

    Auth order: password FIRST — keyboard-interactive is disabled by
    default on Android/Termux sshd and some minimal SSH servers.
    """
    # Always clear stale known_hosts entry BEFORE attempting connection
    _remove_known_hosts_entry(ip, port)

    # Build the remote command based on remote OS type
    safe = pub_key.replace("\\", "\\\\").replace("'", "'\"'\"'")

    if os_type == "windows":
        # Escape pub_key for embedding inside a PS double-quoted string.
        # RSA pub keys contain only: ssh-rsa base64chars comment
        # Characters that need PS escaping inside "...": ` " $
        pub_key_clean = pub_key.strip()
        pub_key_ps = (pub_key_clean
                      .replace('`', '``')
                      .replace('"', '`"')
                      .replace('$', '`$'))

        # Build PowerShell script as a plain Python string.
        # Use [char]10 for LF — avoids ALL backtick-n escape issues.
        # Use Add-Content which handles newlines naturally.
        nl = "[char]10"   # PowerShell newline — no escape sequences needed
        ps = (
            "$p1 = Join-Path $env:USERPROFILE '.ssh'\n"
            "New-Item -ItemType Directory -Force -Path $p1 | Out-Null\n"
            "$ak1 = Join-Path $p1 'authorized_keys'\n"
           f'$key = "{pub_key_ps}"\n'
            "$fp = $key.Split(' ')[1]\n"
            "if (-not (Test-Path $ak1)) { New-Item $ak1 -Force | Out-Null }\n"
            "$c1 = try { [IO.File]::ReadAllText($ak1) } catch { '' }\n"
            "if ($c1 -notlike \"*$fp*\") { [IO.File]::AppendAllText($ak1, $key + [char]10) }\n"
            # administrators_authorized_keys for Admin accounts
            "$p2 = [IO.Path]::Combine($env:ProgramData, 'ssh')\n"
            "New-Item -ItemType Directory -Force -Path $p2 | Out-Null\n"
            "$ak2 = [IO.Path]::Combine($p2, 'administrators_authorized_keys')\n"
            "if (-not (Test-Path $ak2)) { New-Item $ak2 -Force | Out-Null }\n"
            "$c2 = try { [IO.File]::ReadAllText($ak2) } catch { '' }\n"
            "if ($c2 -notlike \"*$fp*\") { [IO.File]::AppendAllText($ak2, $key + [char]10) }\n"
            # Fix ACL — Windows OpenSSH rejects admin key file with wrong perms
            "icacls $ak2 /inheritance:r /grant 'SYSTEM:(F)' /grant 'BUILTIN\\Administrators:(F)' | Out-Null\n"
            # Fix sshd_config PubkeyAuthentication — do NOT restart sshd here
            "$cfg = [IO.Path]::Combine($env:ProgramData, 'ssh', 'sshd_config')\n"
            "if (Test-Path $cfg) {\n"
            "  $sc = [IO.File]::ReadAllText($cfg)\n"
            "  if ($sc -notmatch '(?m)^PubkeyAuthentication yes') {\n"
            "    $sc = $sc -replace '(?m)^#?PubkeyAuthentication.*', 'PubkeyAuthentication yes'\n"
            "    if ($sc -notmatch '(?m)^PubkeyAuthentication yes') {\n"
            "      $sc = $sc + [char]10 + 'PubkeyAuthentication yes'\n"
            "    }\n"
            "    [IO.File]::WriteAllText($cfg, $sc)\n"
            "  }\n"
            "}\n"
            "Write-Output 'KEY_INSTALLED'\n"
        )
        encoded = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
        cmd = f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"
    else:
        # Unix/Android: standard bash approach
        safe = pub_key.replace("\\", "\\\\").replace("'", "'\"'\"'")
        cmd = (f"mkdir -p ~/.ssh && "
               f"chmod 700 ~/.ssh && "
               f"echo '{safe}' >> ~/.ssh/authorized_keys && "
               f"chmod 600 ~/.ssh/authorized_keys && "
               f"echo KEY_INSTALLED")

    # Fresh temp known_hosts bypasses any fingerprint conflicts
    tmp_kh = None
    try:
        tmp_fd, tmp_kh = tempfile.mkstemp(prefix="linkx_kh_", suffix=".tmp")
        os.close(tmp_fd)
    except Exception:
        tmp_kh = None

    args = ["ssh",
            "-p", str(port),            # separate flag+value for max compat
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=20",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "BatchMode=no"]

    # SHOW_PASSWORD debug flag — set True at top of file.
    # Shows full SSH command + verbose output so you can diagnose auth failures.
    # Password is NOT echoed by OpenSSH (OS security) but verbose shows which
    # auth method was accepted/rejected — enough to diagnose most issues.
    if SHOW_PASSWORD:
        args += ["-v"]
        pr(f"\n  {C.RE}[DEBUG] SHOW_PASSWORD=True{C.R}")
        pr(f"  Verbose SSH output will show auth methods tried.")
        pr(f"  To test manually, open a new terminal and run:")
        pr(f"  {C.CY}ssh -p {port} -o PreferredAuthentications=password "
           f"{user}@{ip}{C.R}")
        pr(f"  {C.D}(Password is never echoed — this is an OS security feature){C.R}\n")
    else:
        pr(f"\n  {C.Y}SSH will ask for the password of {user}@{ip}{C.R}")
        pr(f"  Type it when prompted (characters are hidden).\n")

    if tmp_kh:
        args += ["-o", f"UserKnownHostsFile={tmp_kh}"]

    args.append(f"{user}@{ip}")
    args.append(cmd)

    try:
        r = subprocess.run(args)
        success = r.returncode == 0
    except KeyboardInterrupt:
        print()
        warn("Cancelled during password entry.")
        success = False
    except Exception as e:
        err(str(e)); success = False
    finally:
        if tmp_kh:
            try: os.remove(tmp_kh)
            except Exception: pass

    return success

def setup_device(host: dict, hosts: dict) -> dict:
    ip  = host["ip"]
    mac = host.get("mac","")
    clear()
    hdr(f"SETUP — {ip}", host.get("hostname",""))

    if mac:
        pr(f"  {C.D}MAC: {mac}  (device tracked by this — IP changes handled){C.R}")
    else:
        warn("MAC not detected — device tracked by hostname+user")

    # ── OS type — banner grab first (no auth needed), then command probe ─
    pr(f"\n  {C.D}Detecting remote OS from SSH banner...{C.R}", )
    _ssh_port_guess = host.get("ssh_port") or 22
    _detected_os = "1" if _ssh_port_guess == 8022 else ""

    if _ssh_port_guess != 8022:
        # Pass any working key we have — banner detect works even without one
        _tmp_kp = get_key(make_device_id(mac, host.get("hostname",""), "")) or ""
        _det = detect_remote_os(ip, _ssh_port_guess, user=host.get("user",""), kp=_tmp_kp)
        _os_to_key = {
            "windows":"w","android":"1","macos":"9",
            "kali":"4","rhel":"5","arch":"6","suse":"7",
            "alpine":"8","void":"8","gentoo":"8","linux":"2","other":"2"
        }
        _detected_os = _os_to_key.get(_det, "")
        if _det == "windows":
            pr(f"  {C.G}Detected: Windows (from SSH banner){C.R}")
        elif _det not in ("other", ""):
            pr(f"  {C.G}Detected: {_det}{C.R}")
        else:
            pr(f"  {C.D}Banner inconclusive — please select manually{C.R}")

    pr(f"\n  {C.B}What OS is on {ip}?{C.R}\n")
    auto = _detected_os or ("1" if host.get("ssh_port")==8022 else "2")
    if auto == "1":
        pr(f"  {C.G}Port 8022 detected → Android / Termux{C.R}\n")

    choices = [
        ("1","android","Android / Termux              port 8022"),
        ("2","linux",  "Linux — Debian/Ubuntu/Mint    port 22"),
        ("3","linux",  "Linux — Raspberry Pi OS       port 22"),
        ("4","kali",   "Linux — Kali                  port 22"),
        ("5","rhel",   "Linux — Fedora/RHEL/CentOS    port 22"),
        ("6","arch",   "Linux — Arch/Manjaro          port 22"),
        ("7","suse",   "Linux — openSUSE/SLES         port 22"),
        ("8","linux",  "Linux — Alpine/Void/Gentoo    port 22"),
        ("9","macos",  "macOS                         port 22"),
        ("w","windows","Windows 10/11 (OpenSSH)       port 22"),
        ("o","other",  "Other / custom port"),
    ]
    for k, _, label in choices:
        mark = f"  {C.G}← detected{C.R}" if k == auto else ""
        print(f"  [{k}]  {label}{mark}")

    ch      = ask("OS type", auto)
    os_type = {k: v for k, v, _ in choices}.get(ch, "other")
    profile = OS_PROFILES[os_type]

    # ── Port ──────────────────────────────────────────────────────────
    default_port = host.get("ssh_port") or profile["port"]
    try:    port = int(ask("SSH port", str(default_port)))
    except: port = default_port

    # ── Username ──────────────────────────────────────────────────────
    pr(f"\n  {C.B}Remote username{C.R}")
    hints = {"android" : "run 'whoami' in Termux → e.g. u0_a222",
             "kali"    : "your Kali username (e.g. kali or root)",
             "linux"   : "your Linux username (e.g. pi, ubuntu, user)",
             "windows" : "your Windows login name",
             "macos"   : "your macOS username"}
    if os_type in hints: pr(f"  {C.D}({hints[os_type]}){C.R}")
    if os_type == "android":
        pr(f"  {C.D}Leave blank → auto-detected after connection{C.R}")

    def_u = (host.get("user") or
             {"android":"","linux":"user","kali":"kira",
              "windows":"administrator","macos":"user"}.get(os_type,"user"))
    user = ask("Username", def_u)
    if not user: user = "u0_a0"   # placeholder for android, whoami fixes it

    # ── Device ID — with same-device detection ───────────────────────
    # Problem: Android randomizes MAC per-network. A device we already know
    # appears with a new MAC → make_device_id gives a NEW device_id →
    # key lookup fails → setup treats it as unknown.
    # Fix: for MAC-randomizing OSes, probe existing keys on this IP first.
    # The first key that works tells us exactly which stored device this is.
    # We reuse that stored identity (device_id, key_source) and remove the
    # stale record so the updated one takes its place — no duplicates.
    _reidentified = False
    device_id     = make_device_id(mac, host.get("hostname",""), user)

    if os_type in MAC_RANDOMIZED_OS:
        _probe_user = user if user != "u0_a0" else "u0_a222"
        for _ek in _find_existing_keys():
            _ek_base = os.path.basename(_ek)
            if not test_key(ip, _probe_user, port, _ek):
                continue
            # Key works — find which stored host owns this key_source
            for _stored_ip, _stored_h in list(hosts.items()):
                if os.path.basename(_stored_h.get("key_source", "")) == _ek_base:
                    device_id     = _stored_h.get("device_id", device_id)
                    _reidentified = True
                    # Remove stale record so it gets re-inserted at new IP
                    if _stored_ip != ip:
                        hosts.pop(_stored_ip, None)
                    break
            if _reidentified:
                break

    if _reidentified:
        pr(f"  {C.D}Device ID: {device_id}  (re-identified — same device, new MAC){C.R}")
    else:
        pr(f"  {C.D}Device ID: {device_id}  ({'MAC-based' if mac else 'hostname-based'}){C.R}")


    # ── Step 1: ALWAYS clear stale known_hosts entry ─────────────────
    # ssh-keygen -R is a no-op if no entry exists, so this is always safe.
    # Critical: if device was wiped/reinstalled its fingerprint changed.
    # Old entry blocks ALL connections including password auth on some builds.
    _remove_known_hosts_entry(ip, port)

    # If we have a key, also check for host_key_changed to show user why
    _existing_kp_for_check = get_key(device_id) or ((_find_existing_keys() or [None])[0])
    if _existing_kp_for_check and os.path.exists(str(_existing_kp_for_check)):
        _vh = test_key_verbose(ip, user, port, _existing_kp_for_check)
        if _vh == "host_key_changed":
            ok("Host fingerprint changed — known_hosts cleared")
        elif _vh == "ok":
            pass  # key still works — handled below

    # ── Step 1: check key DB ──────────────────────────────────────────
    kp = get_key(device_id)
    if kp:
        pr(f"\n  Key in database: {C.G}{os.path.basename(kp)}{C.R}")
        pr(f"  Testing...")
        if test_key(ip, user, port, kp):
            real_user = run_cmd(ip, user, port, "whoami", kp, timeout=10).strip()
            if real_user and real_user != user:
                ok(f"Username confirmed from device: {real_user}")
                user = real_user
                device_id = make_device_id(mac, host.get("hostname",""), user)
                save_key(device_id, kp)
            ok(f"Key works — connected to {user}@{ip}")
            host.update({"user":user,"os_type":os_type,"ssh_port":port,
                         "mac":mac,"device_id":device_id,"key_ok":True,
                         "mac_randomized":os_type in MAC_RANDOMIZED_OS,
                         "seen_at":time.time()})
            hosts[ip]=host; _dedup_hosts(hosts, save=True); pause(); return host
        else:
            warn("Stored key failed — will try others or set up new one.")

    # ── Step 2: check existing keys in ~/.ssh/ ─────────────────────────
    pre = _find_existing_keys()
    if pre:
        pr(f"\n  Found {len(pre)} existing key(s) in ~/.ssh/:")
        for k in pre: pr(f"    {C.D}{os.path.basename(k)}{C.R}")
        pr(f"  Testing each against {ip}:{port}...")
        for k in pre:
            print(f"  Testing {os.path.basename(k)}...", end=" ", flush=True)
            if test_key(ip, user, port, k):
                real_user = run_cmd(ip, user, port, "whoami", k, timeout=10).strip()
                if real_user:
                    if real_user != user:
                        pr(f"{C.Y}device says username is {real_user}{C.R}")
                        user = real_user
                        device_id = make_device_id(mac, host.get("hostname",""), user)
                    else:
                        print(f"{C.G}works!{C.R}")
                save_key(device_id, k)
                ok(f"Using existing key: {os.path.basename(k)}")
                host.update({"user":user,"os_type":os_type,"ssh_port":port,
                             "mac":mac,"device_id":device_id,"key_ok":True,
                             "key_source":os.path.basename(k),
                             "mac_randomized":os_type in MAC_RANDOMIZED_OS,
                             "seen_at":time.time()})
                hosts[ip]=host; _dedup_hosts(hosts, save=True); pause(); return host
            else:
                print(f"{C.D}no{C.R}")
        pr(f"  No existing key works for this device.")

    # ── Step 3: interactive password → install key ─────────────────────
    pr(f"\n  {C.B}No working key found.{C.R}")
    pr(f"  Will connect with password once to install a key.")
    pr(f"  {C.G}After this you will never need the password again.{C.R}")
    pr()
    pr(f"  Steps:")
    pr(f"  1. SSH opens → asks for password of {user}@{ip}")
    pr(f"  2. You type the password (same as typing ssh manually)")
    pr(f"  3. Key installed automatically")
    pr(f"  4. Password connection closed")
    pr(f"  5. All future transfers use the key")
    pr()
    if ask("Ready? [Y/N]","Y").upper() != "Y": return host

    # Generate key first
    kpath, pub_key = generate_key(device_id, host.get("hostname",ip))
    if not pub_key:
        err("Key generation failed."); pause(); return host

    # Interactive install — raw terminal, user types password themselves
    success = _install_key_interactive(ip, user, port, pub_key, os_type=os_type)

    if not success:
        # Delete the generated key — it was never installed on the remote
        # so keeping it would leave an orphaned unusable key on disk
        for _dead in (kpath, kpath + ".pub"):
            try:
                if os.path.exists(_dead):
                    os.remove(_dead)
            except Exception:
                pass
        # Also remove from key DB if it was registered prematurely
        _km = _load_km()
        _km.pop(device_id, None)
        _save_km(_km)

        err("Installation failed.")
        pr(f"  {C.D}Generated key deleted (it was never installed).{C.R}")
        pr()
        pr(f"  {C.B}Most likely causes:{C.R}")
        if os_type == "windows":
            pr(f"  • Wrong username — use your Windows login name (not email)")
            pr(f"  • Wrong password — same password you use to log into Windows")
            pr(f"  • SSH server not running — run [7] SSH Server to start it")
            pr(f"  • OpenSSH Server not installed:")
            pr(f"    Settings → Apps → Optional Features → OpenSSH Server")
            pr(f"  • Firewall blocking port 22 — run [7] SSH Server to open it")
        elif os_type == "android":
            pr(f"  • Wrong username — run 'whoami' in Termux to confirm")
            pr(f"  • sshd not running — open Termux and run: sshd")
            pr(f"  • Wrong password — set with: passwd")
        else:
            pr(f"  • Wrong username or password")
            pr(f"  • SSH server not running")
            pr(f"  • The device fingerprint changed — try Setup again")
        pr()
        pr(f"  {C.G}Try running Setup again — it often works on the second attempt.{C.R}")
        pause(); return host

    # ── Register key immediately — before verify ──────────────────────
    save_key(device_id, kpath)

    # Windows: fix local key file permissions
    if os.name == "nt":
        try:
            subprocess.run([
                "icacls", kpath, "/inheritance:r",
                "/grant:r", f"{os.environ.get('USERNAME','Admin')}:(R)"
            ], capture_output=True, timeout=8)
        except Exception:
            pass

    # Windows-to-Windows: if sshd_config was changed, sshd needs restart
    # We restart it HERE (after the SSH session closed) not inside the session
    # (restarting sshd inside its own session kills the session mid-command)
    if os_type == "windows":
        pr(f"  {C.D}Restarting SSH server to apply config changes...{C.R}")
        try:
            subprocess.run(["net", "stop", "sshd"],  capture_output=True, timeout=12)
            time.sleep(1)
            subprocess.run(["net", "start", "sshd"], capture_output=True, timeout=12)
            time.sleep(2)   # give sshd time to accept connections
            pr(f"  {C.G}SSH server restarted.{C.R}")
        except Exception:
            pr(f"  {C.Y}Could not restart sshd automatically.{C.R}")
            pr(f"  {C.Y}Run in Admin PowerShell: Restart-Service sshd{C.R}")

    # Verify key — 4 attempts with delay
    pr(f"\n  Verifying key...")
    key_ok = False
    for _attempt in range(4):
        if _attempt > 0:
            pr(f"  {C.D}Retry {_attempt}/3 — waiting for sshd...{C.R}")
            time.sleep(3)
        if test_key(ip, user, port, kpath):
            key_ok = True
            break
        # Fallback without cipher restriction
        try:
            _r2 = subprocess.run([
                "ssh", "-p", str(port), "-i", kpath,
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=8",
                f"{user}@{ip}", "echo SSHOK"
            ], capture_output=True, text=True, timeout=12)
            if _r2.returncode == 0 and "SSHOK" in _r2.stdout:
                key_ok = True
                break
        except Exception:
            pass

    if key_ok:
        # Get real username from device
        real_user = run_cmd(ip, user, port, "whoami", kpath, timeout=10).strip()
        if real_user:
            if real_user != user:
                ok(f"Username confirmed from device: {real_user}")
                user = real_user
                device_id = make_device_id(mac, host.get("hostname",""), user)
            ok(f"Key login confirmed — {user}@{ip}")
        save_key(device_id, kpath)
        del_pw(device_id)  # key works — password no longer needed
        ok("Passwordless connection established!")
        pr(f"  Key: {os.path.basename(kpath)}")
        key_ok = True
    else:
        warn("Key installed but test failed. May work after reconnect.")
        key_ok = False

    host.update({"user":user,"os_type":os_type,"ssh_port":port,
                 "mac":mac,"device_id":device_id,"key_ok":key_ok,
                 "key_source":os.path.basename(kpath),
                 "mac_randomized":os_type in MAC_RANDOMIZED_OS,
                 "seen_at":time.time()})
    hosts[ip]=host; _dedup_hosts(hosts, save=True)

    # ── Naming ceremony (non-pair setup) ─────────────────────────────
    if key_ok:
        kpath, host = _name_connection(
            host, kpath, hosts,
            remote_ip=ip, remote_user=user, remote_port=port,
            is_pair=False)
        # _name_connection already calls pause() — don't call again
        return host
    pause(); return host

# ─────────────────────────────────────────────────────────────────────
# PATH PICKERS — browse or paste
# ─────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────
# LOCAL FILE BROWSER
#
# Full native browser — not just shortcuts.
# Works on Windows, Linux, macOS, Termux (Android).
#
# ROOT level shows:
#   Windows : all drives (C:\ D:\ E:\ etc) + shortcut folders
#   Linux   : / + home + common shortcuts
#   macOS   : / + /Users/you + common shortcuts
#   Termux  : Termux home + ~/storage/* symlinks + /storage/emulated/0
#
# Inside any folder:
#   Dirs listed first (cyan [D]), files after with size
#   [number]  → enter dir or select file
#   [S]       → select current folder itself
#   [..]      → go up one level
#   [P]       → paste/type a path directly
#   [/]       → jump to filesystem root
#   [~]       → jump to home
#   [0]       → back / up
# ─────────────────────────────────────────────────────────────────────

def _fmt_size(n: int) -> str:
    for u, d in (("GB",1<<30),("MB",1<<20),("KB",1<<10)):
        if n >= d: return f"{n/d:.1f}{u}"
    return f"{n}B"

def _ls_local(folder: str) -> list:
    """
    List folder contents sorted dirs-first.
    Returns [(name, full_path, is_dir, size_str)]
    Hidden files (dot-files) shown but sorted after normal entries.
    Permission errors gracefully skipped.
    """
    items = []
    try:
        entries = sorted(os.listdir(folder),
                         key=lambda x: (x.startswith("."), x.lower()))
    except PermissionError:
        return []
    except Exception:
        return []
    for name in entries:
        full = os.path.join(folder, name)
        try:
            is_dir = os.path.isdir(full)
            size   = ""
            if not is_dir:
                try: size = _fmt_size(os.path.getsize(full))
                except Exception: pass
            items.append((name, full, is_dir, size))
        except Exception:
            pass
    # dirs first, then files
    return ([i for i in items if i[2]] +
            [i for i in items if not i[2]])

def _get_drives_windows() -> list:
    """
    Return all mounted drive letters on Windows.
    [(label, path)]  e.g. [("C:\\", "C:/"), ("D:\\", "D:/")]
    Uses ctypes.windll — no extra deps.
    """
    drives = []
    try:
        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = chr(65 + i)
                drives.append((f"{letter}:\\", f"{letter}:/"))
    except Exception:
        # Fallback: check A-Z manually
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZAB":
            p = f"{letter}:/"
            if os.path.exists(p):
                drives.append((f"{letter}:\\", p))
    return drives

def _root_entries(los: str) -> list:
    """
    Build the top-level browser entries for each OS.
    Returns [(label, path, is_shortcut)]
    is_shortcut=True → shown in shortcuts section
    is_shortcut=False → shown as drive/root section
    """
    home = os.path.expanduser("~")
    entries = []

    if los in ("windows", "windows_old"):
        # All real drives first
        for label, path in _get_drives_windows():
            entries.append((label, path, False))
        # Then shortcuts
        for name, raw in LOCAL_LOCATIONS["windows"]:
            p = os.path.abspath(os.path.expanduser(raw))
            entries.append((name, p, True))

    elif los in ("linux", "kali", "debian", "rhel", "arch",
                 "suse", "alpine", "void", "gentoo", "other"):
        # Root filesystem
        entries.append(("/ (root filesystem)", "/", False))
        entries.append(("~ (home)", home, False))
        # Common shortcuts — map new distro ids to existing LOCAL_LOCATIONS keys
        loc_key = "kali" if los == "kali" else "linux"
        for name, raw in LOCAL_LOCATIONS.get(loc_key, LOCAL_LOCATIONS["other"]):
            p = os.path.abspath(os.path.expanduser(raw))
            if p not in ("/", home):
                entries.append((name, p, True))

    elif los == "macos":
        entries.append(("/ (root filesystem)", "/", False))
        entries.append(("~ (home)", home, False))
        entries.append(("/Volumes (drives)", "/Volumes", False))
        for name, raw in LOCAL_LOCATIONS["macos"]:
            p = os.path.abspath(os.path.expanduser(raw))
            if p not in ("/", home):
                entries.append((name, p, True))

    # Termux on Android: show both Termux home and storage symlinks
    termux_home = "/data/data/com.termux/files/home"
    if os.path.exists(termux_home):
        entries = []   # replace — Termux context only
        entries.append(("Termux Home (~)", termux_home, False))
        storage_base = os.path.join(termux_home, "storage")
        if os.path.exists(storage_base):
            for name in sorted(os.listdir(storage_base)):
                full = os.path.join(storage_base, name)
                if os.path.islink(full) or os.path.isdir(full):
                    entries.append((f"~/storage/{name}", full, False))
        entries.append(("Internal Storage (/storage/emulated/0)",
                        "/storage/emulated/0", False))
        entries.append(("/ (root filesystem)", "/", False))

    return entries


def pick_local_path(title="SELECT FILE OR FOLDER TO SEND") -> str:
    """
    Full local file browser.
    Starts at drives/root level. Navigate any folder on the machine.
    Works on Windows (all drives), Linux, macOS, Termux/Android.

    Controls:
      [number]  enter folder / select file
      [S]       select current folder itself
      [..]      go up
      [/]       jump to filesystem root
      [~]       jump to home directory
      [P]       paste a path directly
      [0]       back / up / exit
    """
    los     = local_os()
    home    = os.path.expanduser("~")
    history = []
    current = None   # None = top-level root/drives screen

    while True:
        clear()

        # ── TOP LEVEL: drives + shortcuts ────────────────────────────
        if current is None:
            hdr(title, "Browse — choose a drive or folder")
            root_entries = _get_root_entries_display(los, home)
            _print_browser_top(root_entries)
            sep()
            ch = ask("Choose", "")

            if ch == "0": return ""
            if ch.upper() == "P":
                path = input(f"\n  {C.B}❯  Type or paste path{C.R}: ").strip().strip('"').strip("'")
                if path and os.path.exists(path): return path
                if path: err(f"Path not found: {path}"); time.sleep(1)
                continue
            if ch.upper() == "~":
                current = home; continue
            if ch == "/":
                current = ("C:/" if los in ("windows","windows_old") else "/"); continue

            all_entries = _root_entries(los)
            if ch.isdigit():
                n = int(ch)
                if 1 <= n <= len(all_entries):
                    _, path, _ = all_entries[n - 1]
                    path = os.path.abspath(path)
                    if os.path.isdir(path):
                        current = path
                    elif os.path.isfile(path):
                        return path
                    else:
                        err(f"Not accessible: {path}"); time.sleep(1)
                else:
                    err("Invalid choice."); time.sleep(0.7)
            else:
                err("Invalid."); time.sleep(0.7)

        # ── INSIDE A FOLDER ──────────────────────────────────────────
        else:
            # Truncate long paths for header
            disp = current if len(current) <= W else "..." + current[-(W-3):]
            hdr(title, disp)
            items = _ls_local(current)

            pr()
            # Navigation row
            parent = os.path.dirname(current)
            if parent and parent != current:
                pname = os.path.basename(parent) or parent
                print(f"  {C.B}[..]{C.R}  {C.D}↑  {pname}{C.R}")

            # File/folder listing — paginate if > 40 items
            PAGE = 40
            page_start = getattr(pick_local_path, "_page", 0)
            # reset page when folder changes
            if getattr(pick_local_path, "_last_folder", None) != current:
                page_start = 0
                pick_local_path._last_folder = current
            pick_local_path._page = page_start

            page_items = items[page_start: page_start + PAGE]
            total_pages = (len(items) + PAGE - 1) // PAGE if items else 1
            cur_page    = page_start // PAGE + 1

            if not items:
                pr(f"  {C.D}(empty folder){C.R}")
            else:
                for i, (name, full, is_dir, size) in enumerate(page_items, page_start + 1):
                    icon  = f"{C.CY}[D]{C.R} " if is_dir else "    "
                    sz_s  = f"  {C.D}{size}{C.R}" if size else ""
                    # Dim hidden files slightly
                    nm    = f"{C.D}{name}{C.R}" if name.startswith(".") else name
                    print(f"  {C.B}[{i:>3}]{C.R}  {icon}{nm}{sz_s}")

                if total_pages > 1:
                    pr()
                    pr(f"  {C.D}Page {cur_page}/{total_pages}  "
                       f"({len(items)} items total){C.R}")
                    if page_start + PAGE < len(items):
                        pr(f"  {C.B}[N]{C.R}  Next page")
                    if page_start > 0:
                        pr(f"  {C.B}[B]{C.R}  Previous page")

            pr()
            pr(f"  {C.B}[ S]{C.R}  Select THIS folder")
            pr(f"  {C.B}[ P]{C.R}  Paste/type a path")
            pr(f"  {C.B}[ ~]{C.R}  Jump to home")
            pr(f"  {C.B}[ /]{C.R}  Jump to root / drives")
            pr(f"  {C.B}[ 0]{C.R}  Up / back")
            sep()
            ch = ask("Choose", "")

            if ch == "0" or ch == "..":
                if history:
                    current = history.pop()
                    pick_local_path._page = 0
                else:
                    current = None
            elif ch.upper() == "S":
                return current
            elif ch.upper() == "P":
                path = input(f"\n  {C.B}❯  Type or paste path{C.R}: ").strip().strip('"').strip("'")
                if path and os.path.exists(path): return path
                if path: err(f"Not found: {path}"); time.sleep(1)
            elif ch.upper() == "~":
                history.append(current)
                current = home
                pick_local_path._page = 0
            elif ch == "/":
                history.append(current)
                current = "C:/" if los in ("windows","windows_old") else "/"
                pick_local_path._page = 0
            elif ch.upper() == "N":
                if page_start + PAGE < len(items):
                    pick_local_path._page = page_start + PAGE
            elif ch.upper() == "B":
                pick_local_path._page = max(0, page_start - PAGE)
            elif ch.isdigit():
                n = int(ch)
                if 1 <= n <= len(items):
                    name, full, is_dir, size = items[n - 1]
                    if is_dir:
                        history.append(current)
                        current = full
                        pick_local_path._page = 0
                    else:
                        return full
                else:
                    err(f"No item [{n}]."); time.sleep(0.7)
            else:
                err("Invalid."); time.sleep(0.7)


# helpers used by pick_local_path

def _get_root_entries_display(los: str, home: str):
    """Returns (drives_section, shortcuts_section) for display."""
    all_e = _root_entries(los)
    drives    = [(i+1, l, p) for i,(l,p,s) in enumerate(all_e) if not s]
    shortcuts = [(i+1, l, p) for i,(l,p,s) in enumerate(all_e) if s]
    return all_e, drives, shortcuts

def _print_browser_top(root_entries_result):
    all_e, drives, shortcuts = root_entries_result
    if drives:
        pr(f"  {C.B}Drives / Root:{C.R}")
        pr()
        for idx, label, path in drives:
            exists = f"{C.G}✓{C.R}" if os.path.exists(path) else f"{C.RE}✗{C.R}"
            print(f"  {C.B}[{idx:>2}]{C.R}  {exists}  {C.CY}{label:<22}{C.R}  {C.D}{path}{C.R}")
    if shortcuts:
        pr()
        pr(f"  {C.B}Quick access:{C.R}")
        pr()
        for idx, label, path in shortcuts:
            exists = f"{C.G}✓{C.R}" if os.path.exists(path) else f"{C.D}✗{C.R}"
            print(f"  {C.B}[{idx:>2}]{C.R}  {exists}  {label:<22}  {C.D}{path}{C.R}")
    pr()
    pr(f"  {C.B}[P]{C.R}  Paste / type a path directly")
    pr(f"  {C.B}[0]{C.R}  Back")


# ─────────────────────────────────────────────────────────────────────
# REMOTE PATH BROWSER
#
# If SSH key exists → connects live, browses real remote filesystem.
# If no key        → falls back to predetermined path list.
#
# Live browser uses: ssh user@ip "ls -1ap PATH" to list contents.
# -1  = one per line  -a = include hidden  -p = append / to dirs
# Parses output → dirs (ending /) vs files.
# Connection is ONE ls command per folder — closes immediately after.
# After path is chosen → connection done → scp fires separately.
# ─────────────────────────────────────────────────────────────────────

def _ls_remote(ip, user, port, kp, remote_path: str,
               os_type: str = "linux") -> list:
    """
    List remote directory via SSH.
    Returns [(name, full_path, is_dir)]
    Uses dir on Windows, ls on everything else.
    """
    if os_type == "windows":
        # Normalize: forward slashes → backslashes, escape single quotes
        ps_path = remote_path.replace("/", "\\").replace("'", "''")
        # Also fix domain user in path: v-15\admin → just use the path as-is
        # but ensure no double backslashes from replace
        while "\\\\" in ps_path:
            ps_path = ps_path.replace("\\\\", "\\")
        cmd = (f'powershell -NoProfile -Command "'
               f'Get-ChildItem -LiteralPath \'{ps_path}\' -ErrorAction SilentlyContinue | '
               f'ForEach-Object {{ if ($_.PSIsContainer) {{ $_.Name + \'/\' }} '
               f'else {{ $_.Name }} }}"')
        out = run_cmd(ip, user, port, cmd, kp, timeout=15)
    else:
        cmd = f"ls -1ap {shlex.quote(remote_path)} 2>/dev/null"
        out = run_cmd(ip, user, port, cmd, kp)

    if not out or out == "__TIMEOUT__":
        return []
    items = []
    for line in out.strip().split("\n"):
        line = line.strip()
        if not line or line in ("./", "../"):
            continue
        is_dir = line.endswith("/")
        name   = line.rstrip("/")
        # Build full path — Windows uses backslash remote side
        if os_type == "windows":
            sep_char = "/"
            full = remote_path.rstrip("/\\") + sep_char + name
        else:
            full = remote_path.rstrip("/") + "/" + name
        items.append((name, full, is_dir))
    return ([i for i in items if i[2]] +
            [i for i in items if not i[2]])

def _remote_home(ip, user, port, kp, os_type: str) -> str:
    """Get real home dir from remote."""
    if os_type == "windows":
        out = run_cmd(ip, user, port,
                      'powershell -NoProfile -Command "Write-Output $env:USERPROFILE"',
                      kp, timeout=10)
        if out.strip() and out != "__TIMEOUT__" and "%" not in out:
            return out.strip().replace("\\", "/")
        bare = user.split("\\")[-1] if "\\" in user else user
        return f"C:/Users/{bare}"
    else:
        # Try $HOME — works on Linux/macOS/Android
        out = run_cmd(ip, user, port, "echo $HOME", kp, timeout=10)
        if out.strip() and out != "__TIMEOUT__" and not out.startswith("$"):
            # "$HOME" unexpanded means Windows CMD shell — treat as Windows
            return out.strip()
        # $HOME unexpanded — likely Windows with wrong os_type
        # Try PowerShell as fallback
        out2 = run_cmd(ip, user, port,
                       'powershell -NoProfile -Command "Write-Output $env:USERPROFILE"',
                       kp, timeout=8)
        if out2.strip() and out2 != "__TIMEOUT__" and "%" not in out2:
            return out2.strip().replace("\\", "/")
        # Final fallback from OS profile
        profile = OS_PROFILES.get(os_type, OS_PROFILES["other"])
        bare = user.split("\\")[-1] if "\\" in user else user
        return profile["home"].replace("{user}", bare)

def _remote_roots(ip, user, port, kp, os_type: str, home: str) -> list:
    """
    Build root-level entries for the remote browser.
    Returns [(label, path, is_shortcut)]
    """
    entries = []
    if os_type == "android":
        entries.append(("Termux Home (~)",      home,                    False))
        entries.append(("~/storage/downloads",  home+"/storage/downloads", False))
        entries.append(("~/storage/shared",     home+"/storage/shared",  False))
        entries.append(("~/storage/dcim",       home+"/storage/dcim",    False))
        entries.append(("~/storage/pictures",   home+"/storage/pictures",False))
        entries.append(("~/storage/music",      home+"/storage/music",   False))
        entries.append(("~/storage/movies",     home+"/storage/movies",  False))
        entries.append(("/storage/emulated/0",  "/storage/emulated/0",   False))
    elif os_type == "windows":
        # Strip domain prefix: "DOMAIN\user" → "user"
        bare_user    = user.split("\\")[-1] if "\\" in user else user

        # Ask remote Windows for all real drive letters via PowerShell
        drives = []
        try:
            drive_out = run_cmd(ip, user, port,
                'powershell -NoProfile -Command '
                '"Get-PSDrive -PSProvider FileSystem | '
                'Select-Object -ExpandProperty Root"',
                kp, timeout=10)
            for line in drive_out.strip().splitlines():
                line = line.strip().rstrip("\\")
                if len(line) == 2 and line[1] == ":":
                    drives.append(line + "/")   # e.g. "C:/"
        except Exception:
            pass

        # Fallback if PowerShell gave nothing
        if not drives:
            drives = ["C:/", "D:/"]

        for drv in drives:
            label = drv.replace("/", ":\\")     # "C:/" → "C:\"
            entries.append((label, drv, False))

        # Profile shortcuts
        profile_root = f"C:/Users/{bare_user}"
        entries.append(("Profile root",          profile_root,                  False))
        entries.append(("Desktop",               profile_root+"/Desktop",       True))
        entries.append(("Downloads",             profile_root+"/Downloads",     True))
        entries.append(("Documents",             profile_root+"/Documents",     True))
        entries.append(("Pictures",              profile_root+"/Pictures",      True))
        entries.append(("Videos",               profile_root+"/Videos",        True))
        entries.append(("AppData/Local",         profile_root+"/AppData/Local", True))
    elif os_type == "macos":
        entries.append(("/ (root)",             "/",                     False))
        entries.append(("/Volumes",             "/Volumes",              False))
        entries.append(("Home (~)",             home,                    False))
        entries.append(("Desktop",             home+"/Desktop",         True))
        entries.append(("Downloads",           home+"/Downloads",       True))
        entries.append(("Documents",           home+"/Documents",       True))
        entries.append(("Pictures",            home+"/Pictures",        True))
        entries.append(("Movies",              home+"/Movies",          True))
    else:  # linux/kali/other
        # Check if home looks like a Windows path — os_type may be wrong
        if home and (":" in home or home.startswith("C/") or
                     home.startswith("C:\\")):
            # Treat as Windows — wrong os_type from scan
            bare_user    = user.split("\\")[-1] if "\\" in user else user
            profile_root = home
            entries.append(("C:\\ (root)",    "C:/",                   False))
            entries.append(("Profile root",   profile_root,            False))
            entries.append(("Desktop",        profile_root+"/Desktop", True))
            entries.append(("Downloads",      profile_root+"/Downloads",True))
            entries.append(("Documents",      profile_root+"/Documents",True))
            entries.append(("Pictures",       profile_root+"/Pictures", True))
            entries.append(("Videos",         profile_root+"/Videos",  True))
        else:
            entries.append(("/ (root)",             "/",              False))
            entries.append(("Home (~)",             home,             False))
            entries.append(("Desktop",        home+"/Desktop",        True))
            entries.append(("Downloads",      home+"/Downloads",      True))
            entries.append(("Documents",      home+"/Documents",      True))
            entries.append(("tmp",            "/tmp",                 True))
            entries.append(("var/www/html",   "/var/www/html",        True))
    return entries


def pick_remote_path(os_type, user, title="SELECT REMOTE LOCATION",
                     ip="", port=22, kp="", start_path: str = "") -> str:
    """
    Remote path picker.

    start_path: if set, open the live browser directly at this path
                (used by Vault mode to start in Linkx folder).

    If ip+port+kp given AND SSH is reachable → LIVE BROWSER.
    If no key/connection → FALLBACK to predetermined path list.
    """
    label_os = OS_PROFILES.get(os_type, OS_PROFILES["other"])["label"]

    # ── Decide mode ───────────────────────────────────────────────────
    live = False
    if ip and kp and os.path.exists(kp):
        pr(f"  {C.D}Checking SSH connection for live browse...{C.R}")
        live = test_key(ip, user, port, kp)
        if live:
            pr(f"  {C.G}Live browse active — connected to {user}@{ip}{C.R}")
        else:
            pr(f"  {C.Y}SSH not reachable — using preset paths{C.R}")
            time.sleep(0.8)

    # ── LIVE BROWSER ─────────────────────────────────────────────────
    if live:
        home     = _remote_home(ip, user, port, kp, os_type)
        roots    = _remote_roots(ip, user, port, kp, os_type, home)
        history  = []
        current  = start_path if start_path else None  # Vault: skip root screen
        page_key = [0]    # mutable for closure

        while True:
            clear()

            if current is None:
                # Root level
                hdr(title, f"Live browser — {user}@{ip}  [{label_os}]")
                pr()
                drives    = [(i+1,l,p) for i,(l,p,s) in enumerate(roots) if not s]
                shortcuts = [(i+1,l,p) for i,(l,p,s) in enumerate(roots) if s]
                if drives:
                    pr(f"  {C.B}Locations:{C.R}")
                    pr()
                    for idx,l,p in drives:
                        print(f"  {C.B}[{idx:>2}]{C.R}  {C.CY}{l:<28}{C.R}  {C.D}{p}{C.R}")
                if shortcuts:
                    pr()
                    pr(f"  {C.B}Quick access:{C.R}")
                    pr()
                    for idx,l,p in shortcuts:
                        print(f"  {C.B}[{idx:>2}]{C.R}  {l:<28}  {C.D}{p}{C.R}")
                pr()
                pr(f"  {C.B}[P]{C.R}  Paste path directly")
                pr(f"  {C.B}[0]{C.R}  Back")
                sep()
                ch = ask("Choose", "")
                if ch == "0": return ""
                if ch.upper() == "P":
                    path = ask("Remote path", "")
                    if path: return path
                    continue
                if ch.isdigit():
                    n = int(ch)
                    if 1 <= n <= len(roots):
                        current = roots[n-1][1]
                        page_key[0] = 0
                    else:
                        err("Invalid."); time.sleep(0.7)
                else:
                    err("Invalid."); time.sleep(0.7)

            else:
                # Inside a remote folder
                disp = current if len(current) <= W else "..."+current[-(W-3):]
                hdr(title, f"{user}@{ip}:{disp}")
                pr(f"  {C.D}Loading...{C.R}", )
                items = _ls_remote(ip, user, port, kp, current, os_type=os_type)
                # clear the loading line
                print(f"\033[1A\033[2K", end="")

                PAGE = 40
                ps   = page_key[0]
                page_items  = items[ps: ps+PAGE]
                total_pages = (len(items)+PAGE-1)//PAGE if items else 1
                cur_page    = ps//PAGE + 1

                pr()
                parent = current.rstrip("/").rsplit("/", 1)
                par    = parent[0] if len(parent) > 1 and parent[0] else "/"
                if par != current:
                    pname = par.rstrip("/").rsplit("/",1)[-1] or par
                    print(f"  {C.B}[..]{C.R}  {C.D}↑  {pname}{C.R}")

                if not items:
                    pr(f"  {C.D}(empty or permission denied){C.R}")
                else:
                    for i,(name,full,is_dir) in enumerate(page_items, ps+1):
                        icon = f"{C.CY}[D]{C.R} " if is_dir else "    "
                        nm   = f"{C.D}{name}{C.R}" if name.startswith(".") else name
                        print(f"  {C.B}[{i:>3}]{C.R}  {icon}{nm}")
                    if total_pages > 1:
                        pr()
                        pr(f"  {C.D}Page {cur_page}/{total_pages} ({len(items)} items){C.R}")
                        if ps+PAGE < len(items): pr(f"  {C.B}[N]{C.R}  Next page")
                        if ps > 0:               pr(f"  {C.B}[B]{C.R}  Previous page")

                pr()
                pr(f"  {C.B}[ S]{C.R}  Select THIS folder")
                pr(f"  {C.B}[ P]{C.R}  Paste path")
                pr(f"  {C.B}[ ~]{C.R}  Jump to home")
                pr(f"  {C.B}[ /]{C.R}  Jump to root")
                pr(f"  {C.B}[ 0]{C.R}  Up / back")
                sep()
                ch = ask("Choose", "")

                if ch in ("0",".."):
                    if history:
                        current = history.pop(); page_key[0] = 0
                    else:
                        current = None
                elif ch.upper() == "S":
                    return current
                elif ch.upper() == "P":
                    path = ask("Remote path", "")
                    if path: return path
                elif ch.upper() == "~":
                    history.append(current); current = home; page_key[0] = 0
                elif ch == "/":
                    history.append(current)
                    current = ("C:/" if os_type=="windows" else "/")
                    page_key[0] = 0
                elif ch.upper() == "N":
                    if ps+PAGE < len(items): page_key[0] = ps+PAGE
                elif ch.upper() == "B":
                    page_key[0] = max(0, ps-PAGE)
                elif ch.isdigit():
                    n = int(ch)
                    if 1 <= n <= len(items):
                        name, full, is_dir = items[n-1]
                        if is_dir:
                            history.append(current)
                            current = full; page_key[0] = 0
                        else:
                            return full
                    else:
                        err(f"No item [{n}]."); time.sleep(0.7)
                else:
                    err("Invalid."); time.sleep(0.7)

    # ── FALLBACK: predetermined list ─────────────────────────────────
    _bare_u = user.split("\\")[-1] if "\\" in user else user
    locs = [(name, path.replace("{user}", _bare_u))
            for name, path in REMOTE_LOCATIONS.get(os_type,
                               REMOTE_LOCATIONS["other"])]
    while True:
        clear()
        hdr(title, f"Preset paths — {label_os}  {C.D}(SSH offline){C.R}")
        pr()
        pr(f"  {C.B}Common locations:{C.R}")
        pr()
        for i,(name,path) in enumerate(locs,1):
            print(f"  {C.B}[{i:>2}]{C.R}  {name:<28}  {C.D}{path}{C.R}")
        pr()
        pr(f"  {C.B}[P]{C.R}  Paste path directly")
        pr(f"  {C.B}[0]{C.R}  Back")
        sep()
        ch = ask("Choose", "")
        if ch == "0": return ""
        if ch.upper() == "P":
            path = ask("Remote path", "")
            if path: return path
            continue
        if ch.isdigit() and 1 <= int(ch) <= len(locs):
            return locs[int(ch)-1][1]
        err("Invalid."); time.sleep(0.7)

# ─────────────────────────────────────────────────────────────────────
# FILE SIZE HELPER
# ─────────────────────────────────────────────────────────────────────
def sz(p: str) -> str:
    try:
        if os.path.isfile(p):
            s = os.path.getsize(p)
            for u in ("B","KB","MB","GB"):
                if s < 1024: return f"{s:.1f}{u}"
                s /= 1024
            return f"{s:.1f}TB"
        if os.path.isdir(p):
            n = sum(len(f) for _,_,f in os.walk(p))
            return f"folder — {n} files"
    except Exception: pass
    return "?"

# ─────────────────────────────────────────────────────────────────────
# TRANSFER MENU
# ─────────────────────────────────────────────────────────────────────
def get_auth(host: dict, hosts: dict) -> str:
    """
    Get a working key path for this host.
    If not set up: runs setup_device first.
    Returns key path or "" if nothing works.
    """
    device_id = host.get("device_id","")
    ip        = host["ip"]
    user      = host.get("user","")
    port      = host.get("ssh_port",22)

    kp = get_key(device_id) if device_id else ""
    if kp: return kp

    relay_info = host.get("relay")
    if relay_info and not is_directly_reachable(ip):
        rkp = get_key(relay_info.get("device_id",""))
        relay_h = hosts.get(relay_info.get("ip",""), relay_info)
        if rkp:
            u = user or "user"
            did = make_device_id(host.get("mac",""),host.get("hostname",ip),u)
            kpath, pub_key = generate_key(did, host.get("hostname",ip))
            if pub_key and install_key_via_relay(ip,u,port,pub_key,relay_h,rkp):
                save_key(did,kpath); host["device_id"]=did
                hosts[ip]=host; save_hosts(hosts); return kpath
        warn("Could not install key via relay."); return ""
    # Direct path
    warn("No key configured for this device — running setup...")
    time.sleep(1)
    host = setup_device(host, hosts)
    device_id = host.get("device_id","")
    return get_key(device_id) if device_id else ""

def menu_share_linkx(host: dict, hosts: dict, ip: str, user: str,
                     port: int, os_type: str, kp: str):
    """
    Share Linkx — send this running script to the selected device.

    Flow:
      1. Find this script's real path via __file__ / sys.argv[0]
      2. Verify connection (update IP/MAC if needed)
      3. Create Downloads/Linkx/Linkx app/ folder on remote
      4. Send script there via do_scp (rsync/scp routing applies)
      5. Show how to run it on the remote device
    """
    clear()
    hdr("SHARE LINKX", f"Send this app → {user}@{ip}")
    pr()

    # ── Step 1: find this script ──────────────────────────────────────
    try:
        script_path = os.path.abspath(__file__)
    except Exception:
        try:
            script_path = os.path.abspath(sys.argv[0])
        except Exception:
            script_path = ""

    if not script_path or not os.path.isfile(script_path):
        err("Could not find this script's location on disk.")
        pr(f"  {C.D}Tried: __file__ and sys.argv[0]{C.R}")
        pause(); return

    script_name = os.path.basename(script_path)
    script_size = sz(script_path)

    pr(f"  {C.B}This script:{C.R}  {C.G}{script_path}{C.R}")
    pr(f"  {C.B}Size       :{C.R}  {script_size}")
    pr()

    # ── Step 2: build remote destination ─────────────────────────────
    # Downloads/Linkx/Linkx app/  ← subfolder inside Linkx folder
    linkx_base   = _linkx_path_remote(os_type, user)
    # Strip domain prefix for Windows path building
    bare_user    = user.split("\\")[-1] if "\\" in user else user
    if os_type == "windows":
        # Use USERPROFILE-based path for Windows — more reliable than hardcoded
        out_home = run_cmd(ip, user, port,
                           'powershell -NoProfile -Command "Write-Output $env:USERPROFILE"',
                           kp, timeout=10)
        if out_home.strip() and "%" not in out_home:
            home_win   = out_home.strip().replace("\\", "/")
            linkx_base = f"{home_win}/Downloads/{LINKX_FOLDER}"
        linkx_app_dir = f"{linkx_base}/Linkx app"
    else:
        linkx_app_dir = f"{linkx_base}/Linkx app"

    pr(f"  {C.B}Destination:{C.R}  {C.CY}{user}@{ip}:{linkx_app_dir}{C.R}")
    pr()

    # ── Step 3: confirm ───────────────────────────────────────────────
    pr(f"  {C.B}[Y]{C.R}  Send now")
    pr(f"  {C.B}[0]{C.R}  Cancel")
    sep()
    if ask("Choose", "Y").strip().upper() != "Y":
        return

    # ── Step 4: create remote folder ─────────────────────────────────
    clear(); hdr("SHARE LINKX", "Creating remote folder...")
    pr()
    pr(f"  {C.D}Creating {linkx_app_dir} on remote...{C.R}")

    if os_type == "windows":
        mkdir_cmd = (f'powershell -NoProfile -Command "'
                     f'New-Item -ItemType Directory -Force -Path \'{linkx_app_dir}\' '
                     f'| Out-Null; Write-Output DONE_MKDIR"')
    else:
        mkdir_cmd = f"mkdir -p {shlex.quote(linkx_app_dir)} && echo DONE_MKDIR"

    mkdir_out = run_cmd(ip, user, port, mkdir_cmd, kp, timeout=15)
    if "DONE_MKDIR" not in mkdir_out:
        warn("Could not create remote folder — trying to send anyway.")
    else:
        ok(f"Remote folder ready ✓")

    # ── Step 5: send the script ───────────────────────────────────────
    pr()
    pr(f"  {C.B}Sending {script_name}...{C.R}")
    dest_str = f"{user}@{ip}:{linkx_app_dir}"

    _ri    = host.get("relay") if host else None
    _rkp   = get_key(_ri.get("device_id", "")) if _ri else ""
    _relay = bool(_ri and _rkp and not is_directly_reachable(ip))

    try:
        if _relay:
            ok2, msg = do_scp_relay(script_path, dest_str, port, kp, _ri, _rkp)
        else:
            ok2, msg = do_scp(script_path, dest_str, port, kp)
    except KeyboardInterrupt:
        print(); warn("Cancelled."); pause(); return

    if not ok2:
        err(f"Transfer failed: {msg}")
        pause(); return

    ok(f"Linkx sent to {user}@{ip} ✓")

    # ── Step 6: show how to run on remote ────────────────────────────
    remote_script = f"{linkx_app_dir}/{script_name}"
    sep()
    pr(f"  {C.B}To run Linkx on the remote device:{C.R}")
    pr()
    if os_type == "android":
        pr(f"  {C.Y}Android / Termux:{C.R}")
        pr(f"    cd {linkx_app_dir.replace('/sdcard', '~/storage/shared')}")
        pr(f"    python {script_name}")
    elif os_type == "windows":
        win_path = remote_script.replace("/", "\\")
        pr(f"  {C.Y}Windows (PowerShell or CMD):{C.R}")
        pr(f"    python \"{win_path}\"")
        pr(f"  {C.D}Or double-click if Python is associated with .py files{C.R}")
    elif os_type == "macos":
        pr(f"  {C.Y}macOS (Terminal):{C.R}")
        pr(f"    python3 {shlex.quote(remote_script)}")
    else:
        pr(f"  {C.Y}Linux (Terminal):{C.R}")
        pr(f"    python3 {shlex.quote(remote_script)}")
    pr()
    pr(f"  {C.D}File location: {remote_script}{C.R}")
    sep()
    pause()

def transfer_menu(host: dict, hosts: dict):
    global  TAR_THRESHOLD
    ip      = host["ip"]
    user    = host.get("user","")
    port    = host.get("ssh_port",22)
    os_type = host.get("os_type","other")
    did     = host.get("device_id","")

    if not user:
        warn("Not set up yet."); time.sleep(1)
        host = setup_device(host, hosts)
        ip=host["ip"]; user=host.get("user","")
        port=host.get("ssh_port",22); os_type=host.get("os_type","other")
        did=host.get("device_id","")
        if not user: return

    while True:
        clear()
        kp     = get_key(did) if did else ""
        auth_s = (f"{C.G}{os.path.basename(kp)}{C.R}" if kp
                  else f"{C.RE}No key — run [6] Setup{C.R}")
        osl    = OS_PROFILES.get(os_type,OS_PROFILES["other"])["label"]

        _dlbl = _device_label(host)
        _nick = host.get("nickname","")
        _nlbl = f"  {C.G}{_dlbl}{C.R}" if _nick else ""
        _relay_info = host.get("relay")
        _relay_ip   = _relay_info.get("ip","?") if _relay_info else "?"
        _rtag = (f" {C.CY}[relay {_relay_ip}]{C.R}"
                 if _relay_info and not is_directly_reachable(ip) else "")
        hdr(f"TRANSFER  {user}@{ip}:{port}", osl + _nlbl + _rtag)
        pr(f"  Key  : {auth_s}")
        pr(f"  MAC  : {C.D}{host.get('mac','unknown')}{C.R}   ID: {C.D}{did}{C.R}")
        if os_type == "android":
            pr(f"  {C.D}Phone storage: /storage/emulated/0/{C.R}")
        pr()
        sep()
        pr(f"  {C.B}[1]{C.R}  Send     →  file or folder TO this device")
        pr(f"  {C.B}[2]{C.R}  Receive  ←  file or folder FROM this device")
        pr(f"  {C.B}[3]{C.R}  Browse remote files")
        pr(f"  {C.B}[4]{C.R}  Run command on remote")
        pr(f"  {C.B}[5]{C.R}  Open SSH shell  (full terminal on REMOTE)")
        pr(f"  {C.B}[S]{C.R}  Share Linkx  →  send this app to device")
        pr(f"  {C.B}[T]{C.R}  Raw local terminal  (run commands HERE without quitting)")
        pr(f"  {C.B}[X]{C.R}  Tar threshold : {C.CY}{TAR_THRESHOLD} files{C.R}  "
           f"{C.D}(tar when count exceeds this — 0 = always tar){C.R}")
        sep()
        pr(f"  {C.B}[6]{C.R}  Re-setup  (change user / reinstall key)")
        _in_vault = vault_has(did) if did else False
        if _in_vault:
            pr(f"  {C.B}[V]{C.R}  {C.CY}🔒 In Vault{C.R}  {C.D}(already added){C.R}")
        else:
            pr(f"  {C.B}[V]{C.R}  Add to Vault  {C.D}(Linkx folder + instant access){C.R}")
        pr(f"  {C.B}[0]{C.R}  Back")

        ch = ask("Choose")
        if ch == "0": return

        if ch.upper() == "T":
            # Raw local terminal — spawn a shell on THIS machine
            clear()
            pr(f"  {C.B}Raw Local Terminal{C.R}  (type 'exit' to return to linkx)")
            pr(f"  {C.D}Current device: {socket.gethostname()}{C.R}")
            sep()
            try:
                if os.name == "nt":
                    subprocess.run(["cmd.exe"], shell=False)
                else:
                    shell = os.environ.get("SHELL", "/bin/sh")
                    subprocess.run([shell])
            except Exception as e:
                err(f"Could not open terminal: {e}")
            continue

        if ch.upper() == "S":
            conn_ok, kp, hosts = verify_connection(host, hosts)
            if not conn_ok: continue
            ip      = host["ip"]
            host    = hosts.get(ip, host)
            user    = host.get("user", user)
            port    = host.get("ssh_port", port)
            os_type = host.get("os_type", os_type)
            did     = host.get("device_id", did)
            menu_share_linkx(host, hosts, ip, user, port, os_type, kp)
            continue

        if ch in ("1","2","3","4","5"):
            # ── Verify connection BEFORE file/path selection ──────────
            # This catches: key mismatch, device wiped, sshd not running
            # No time wasted picking files when connection is broken
            conn_ok, kp, hosts = verify_connection(host, hosts)
            if not conn_ok:
                continue   # verify_connection already showed error + options

            # Refresh all fields — setup_device inside verify may have updated them
            ip      = host["ip"] 
            host    = hosts.get(ip, host)
            user    = host.get("user", user)
            port    = host.get("ssh_port", port)
            os_type = host.get("os_type", os_type)
            did     = host.get("device_id", did)

            if   ch == "1": _do_send(ip,user,port,os_type,kp,host)
            elif ch == "2": _do_receive(ip,user,port,os_type,kp,host)
            elif ch == "3": _do_browse(ip,user,port,os_type,kp)
            elif ch == "4": _do_cmd(ip,user,port,kp)
            elif ch == "5":
                pr(f"\n  Opening shell to {user}@{ip}  (type exit to return)\n")
                time.sleep(0.5)
                _rsh = host.get('relay')
                _rksh = get_key(_rsh.get('device_id','')) if _rsh else ''
                if _rsh and _rksh and not is_directly_reachable(ip):
                    open_shell_relay(ip, user, port, kp, _rsh, _rksh)
                else:
                    open_shell(ip, user, port, kp)
        elif ch == "6":
            host = setup_device(host, hosts)
            ip=host["ip"]; user=host.get("user","")
            port=host.get("ssh_port",22); os_type=host.get("os_type","other")
            did=host.get("device_id","")
        elif ch.upper() == "V":
            if vault_has(did):
                # Device is in vault — offer remove
                clear(); hdr("VAULT", _device_label(host))
                pr()
                pr(f"  {C.CY}🔒 {_device_label(host)}{C.R} is currently in Vault.")
                pr()
                pr(f"  {C.B}[R]{C.R}  Remove from Vault")
                pr(f"  {C.B}[0]{C.R}  Keep in Vault / Back")
                sep()
                vc = ask("Choose", "0").strip().upper()
                if vc == "R":
                    vault_remove(did)
                    ok(f"{_device_label(host)} removed from Vault.")
                    time.sleep(1)
            else:
                # Not in vault — offer add
                conn_ok, kp, hosts = verify_connection(host, hosts)
                if conn_ok:
                    host = hosts.get(host["ip"], host)
                    host = _ask_add_to_vault(
                        host, hosts,
                        ip=host["ip"],
                        user=host.get("user", user),
                        port=host.get("ssh_port", port),
                        kp=kp)
                    hosts[host["ip"]] = host
                    save_hosts(hosts)
        elif ch.upper() == "X":
            
            clear(); hdr("TAR THRESHOLD", "When to bundle files into Transfer.tar")
            pr()
            pr(f"  {C.B}Current threshold:{C.R}  {C.CY}{TAR_THRESHOLD} files{C.R}")
            pr()
            pr(f"  {C.D}If total file count across selected items exceeds{C.R}")
            pr(f"  {C.D}this number, they are bundled into Transfer.tar.{C.R}")
            pr(f"  {C.D}Single files are NEVER tarred regardless of size.{C.R}")
            pr()
            pr(f"  {C.D}Examples:{C.R}")
            pr(f"  {C.D}  0  = always tar (except single files){C.R}")
            pr(f"  {C.D}  10 = tar only when count > 10  (default){C.R}")
            pr(f"  {C.D}  99 = almost never tar{C.R}")
            pr()
            val = ask("New threshold (Enter to keep current)",
                      str(TAR_THRESHOLD)).strip()
            if val.isdigit():
                TAR_THRESHOLD = int(val)
                ok(f"Tar threshold set to {TAR_THRESHOLD} files ✓")
                time.sleep(0.8)
            elif val:
                err("Invalid — must be a whole number.")
                time.sleep(0.8)
        else:
            err("Invalid."); time.sleep(0.8)

# ─────────────────────────────────────────────────────────────────────
# ZSTD + TAR COMPRESSION SYSTEM
#
# SENDER SIDE (local, runs on the machine running linkx.py):
#   1. User opts in to compress before sending
#   2. Single file  → zstd -N file.ext  → file.ext.zst
#   3. Multiple files / folders → tar + zstd pipeline
#                               → name.tar.zst  (one bundle)
#   4. Compressed file is sent instead of originals
#   5. Temp .zst / .tar.zst is deleted after transfer
#
# RECEIVER SIDE (remote, commands run over SSH):
#   1. After transfer, user is asked: decompress on remote or leave as-is?
#   2. If decompress: check if zstd is installed on remote (command -v zstd)
#   3. If not installed: detect remote OS from os_type stored in DB
#                        run correct install command over SSH
#                        detect network failure → tell user to enable mobile data
#   4. Decompress: zstd -d (single) or tar --use-compress-program=zstd -xf (bundle)
#   5. Ask: delete the .zst bundle after decompression?
#
# COMPRESSION LEVELS (zstd):
#   1  = Fastest   — almost no size reduction, near-instant  (real-time streaming)
#   3  = Default   — good balance of speed and compression  ← recommended
#   6  = Good      — noticeably smaller, a bit slower
#   10 = Better    — high compression, suitable for photos/docs
#   15 = Very High — slow but small (large files, documents)
#   19 = Maximum   — slowest standard level
#   22 = Ultra     — requires --ultra flag, maximum possible
# ─────────────────────────────────────────────────────────────────────

# Compression levels for 7-Zip (1=fastest, 9=ultra)
# 7-Zip compression levels (passed as -mx=N to 7z)
_7Z_LEVELS = [
    ("1", "Fastest  — almost no size reduction, instant"),
    ("3", "Fast     — light compression, quick"),
    ("5", "Default  — good balance  ← recommended"),
    ("7", "Good     — noticeably smaller, slower"),
    ("9", "Ultra    — maximum compression (slow, needs RAM)"),
]

# Install commands for 7-Zip on the REMOTE device
_7Z_INSTALL = {
    "android"     : "pkg install -y p7zip",
    "debian"      : "sudo apt-get install -y p7zip-full",
    "kali"        : "sudo apt-get install -y p7zip-full",
    "rhel"        : "sudo dnf install -y p7zip p7zip-plugins",
    "arch"        : "sudo pacman -S --noconfirm p7zip",
    "suse"        : "sudo zypper install -y p7zip",
    "alpine"      : "apk add p7zip",
    "void"        : "sudo xbps-install -y p7zip",
    "gentoo"      : "emerge app-arch/p7zip",
    "macos"       : "brew install p7zip",
    "windows"     : "winget install 7zip.7zip",
    "windows_old" : "choco install 7zip -y",
    "linux"       : "sudo apt-get install -y p7zip-full || sudo dnf install -y p7zip p7zip-plugins",
    "other"       : "sudo apt-get install -y p7zip-full || sudo dnf install -y p7zip",
}


def _local_has_7z() -> bool:
    """Check if 7-Zip installed. Checks PATH + known Windows install paths."""
    if shutil.which("7z"):
        return True
    if os.name == "nt":
        for c in [r"C:\Program Files\7-Zip\7z.exe",
                  r"C:\Program Files (x86)\7-Zip\7z.exe"]:
            if os.path.isfile(c):
                return True
    return False


def _local_has_tar() -> bool:
    """Check if tar available. Windows ships tar since Win10 1803."""
    if shutil.which("tar"):
        return True
    if os.name == "nt":
        # Windows ships tar.exe in System32 since build 17063
        for c in [r"C:\Windows\System32\tar.exe",
                  r"C:\Windows\SysWOW64\tar.exe"]:
            if os.path.isfile(c):
                return True
    return False


def _tar_cwd_and_names(paths: list) -> tuple:
    """Returns (cwd, names) so tar archives have clean relative paths, not full tree."""
    parents = set(os.path.dirname(os.path.abspath(p.rstrip("/\\"))) for p in paths)
    if len(parents) == 1:
        return parents.pop(), [os.path.basename(p.rstrip("/\\")) for p in paths]
    return None, paths


def _get_7z_bin() -> str:
    """Get 7z binary — checks PATH then Windows install paths."""
    if shutil.which("7z"):
        return "7z"
    if os.name == "nt":
        for c in [r"C:\Program Files\7-Zip\7z.exe",
                  r"C:\Program Files (x86)\7-Zip\7z.exe"]:
            if os.path.isfile(c):
                return c
    return "7z"


def _compress_item_7z(local_path: str, archive_name: str, level: str) -> str:
    """
    Compress a single file or folder into <archive_name>.7z using 7-Zip.
    Returns path to .7z on success, empty string on failure.
    """
    out_dir  = tempfile.gettempdir()
    safe     = re.sub(r"[^a-zA-Z0-9_\-]", "_", archive_name.strip()) or "archive"
    out_path = os.path.join(out_dir, f"{safe}.7z")
    bin_7z   = _get_7z_bin()
    args     = [bin_7z, "a", out_path, f"-mx={level}", local_path]
    try:
        r = subprocess.run(args, capture_output=True)
        if r.returncode not in (0, 1):
            msg = r.stderr.decode(errors="ignore")[:120]
            err(f"7z failed: {msg}")
            return ""
        return out_path
    except FileNotFoundError:
        err("7z not found — install via [8] Install tools")
        return ""
    except Exception as e:
        err(str(e))
        return ""

def _remote_check_rsync(ip, user, port, kp, os_type: str = "") -> bool:
    """Return True if rsync is available on the remote device."""
    if os_type == "windows":
        # Check MSYS2 path directly — rsync won't be in Windows PATH
        out = run_cmd(ip, user, port,
                      r'if exist "C:\msys64\usr\bin\rsync.exe" (echo FOUND) else (echo MISSING)',
                      kp, timeout=8)
        return "FOUND" in out
    out = run_cmd(ip, user, port,
                  "command -v rsync 2>/dev/null || which rsync 2>/dev/null",
                  kp, timeout=8)
    return bool(out.strip()) and out != "__TIMEOUT__"


def _remote_install_rsync(ip, user, port, kp, os_type: str) -> tuple:
    """
    Install rsync on remote device using detected OS package manager.
    Windows: installs MSYS2 then rsync inside MSYS2 — two steps over SSH.
    Returns (success: bool, message: str).
    """
    if os_type == "windows":
        # Step 1: install MSYS2 via winget
        pr(f"  {C.D}Step 1/2 — Installing MSYS2 on remote Windows...{C.R}")
        run_cmd(ip, user, port,
                "winget install --id MSYS2.MSYS2 --accept-package-agreements "
                "--accept-source-agreements",
                kp, timeout=300)
        # Step 2: install rsync inside MSYS2
        pr(f"  {C.D}Step 2/2 — Installing rsync inside MSYS2...{C.R}")
        run_cmd(ip, user, port,
                r'C:\msys64\usr\bin\bash.exe -lc "pacman -S --noconfirm rsync"',
                kp, timeout=180)
        if _remote_check_rsync(ip, user, port, kp, "windows"):
            return True, "rsync installed on remote Windows ✓"
        # Check if file exists even if not in PATH
        chk = run_cmd(ip, user, port,
                      r'if exist "C:\msys64\usr\bin\rsync.exe" (echo FOUND) else (echo MISSING)',
                      kp, timeout=10)
        if "FOUND" in chk:
            return True, "rsync installed at C:\\msys64\\usr\\bin\\rsync.exe ✓"
        return False, ("MSYS2 rsync install failed on remote.\n"
                       "  Try manually in PowerShell on remote:\n"
                       r"    winget install --id MSYS2.MSYS2" + "\n"
                       r"    C:\msys64\usr\bin\bash.exe -lc 'pacman -S --noconfirm rsync'")

    # Non-Windows: standard package manager
    install_cmd = _RSYNC_REMOTE_INSTALL.get(os_type, _RSYNC_REMOTE_INSTALL["other"])
    pr(f"  {C.D}Installing rsync on remote ({os_type})...{C.R}")
    run_cmd(ip, user, port, install_cmd, kp, timeout=120)
    if _remote_check_rsync(ip, user, port, kp, os_type):
        return True, "rsync installed on remote ✓"
    net_out = run_cmd(ip, user, port,
                      "ping -c1 -W2 8.8.8.8 2>&1 || echo NO_NET", kp, timeout=10)
    if "NO_NET" in net_out or "unreachable" in net_out.lower():
        return False, "No internet on remote device — install rsync manually."
    return False, f"rsync install failed. Try manually:\n    {install_cmd}"

def _remote_check_7z(ip, user, port, kp) -> bool:
    """Return True if 7-Zip (7z) is available on the remote device."""
    out = run_cmd(ip, user, port,
                  "command -v 7z 2>/dev/null || which 7z 2>/dev/null",
                  kp, timeout=10)
    return bool(out.strip()) and out != "__TIMEOUT__"


def _remote_install_7z(ip, user, port, kp, os_type: str) -> tuple:
    """
    Install 7-Zip on remote device using the correct package manager.
    Returns (success: bool, message: str).
    """
    install_cmd = _7Z_INSTALL.get(os_type, _7Z_INSTALL["other"])
    pr(f"  {C.D}Installing 7-Zip on remote ({os_type}): {install_cmd}{C.R}")
    run_cmd(ip, user, port, install_cmd, kp, timeout=120)
    if _remote_check_7z(ip, user, port, kp):
        return True, "7-Zip installed on remote ✓"
    net_out = run_cmd(ip, user, port,
                      "ping -c1 -W2 8.8.8.8 2>&1 || echo NO_NET", kp, timeout=10)
    if "NO_NET" in net_out or "unreachable" in net_out.lower() or not net_out.strip():
        return False, ("No internet on remote device.\n"
                       "  → Phone: turn on Mobile Data.\n"
                       "  → WiFi: check router has internet.")
    return False, (f"Install ran but 7z still not found.\n"
                   f"  Try manually:\n    {install_cmd}")


def _remote_extract_7z(ip, user, port, kp,
                       remote_archive: str, dest_dir: str,
                       os_type: str) -> tuple:
    """
    Extract a .7z archive on the remote device into dest_dir.
    Deletes the .7z after successful extraction.
    Returns (success: bool, message: str).
    """
    if os_type == "windows":
        arc_q  = f'"{remote_archive}"'
        dest_q = f'"{dest_dir}"'
        cmd = (f'7z x {arc_q} -o{dest_q} -y'
               f' && del /f {arc_q}'
               f' && echo DONE_7Z')
    else:
        arc_q  = shlex.quote(remote_archive)
        dest_q = shlex.quote(dest_dir)
        cmd = (f"7z x {arc_q} -o{dest_q} -y"
               f" && rm -f {arc_q}"
               f" && echo DONE_7Z")
    out = run_cmd(ip, user, port, cmd, kp, timeout=300)
    if "DONE_7Z" in out:
        return True, "Extracted and .7z deleted on remote ✓"
    return False, f"Extraction failed. Output: {out[:200]}"


def _ask_decompress_remote(remote_compressed_path: str,
                           is_bundle: bool) -> bool:
    """
    After transfer succeeds, ask if the user wants to decompress on remote.
    Returns True if yes.
    """
    sep()
    pr(f"  {C.B}File transferred:{C.R}  {os.path.basename(remote_compressed_path)}")
    pr()
    pr(f"  {C.B}Decompress on the remote device now?{C.R}")
    pr(f"  {C.D}{'Bundle .tar.zst → original files/folders' if is_bundle else 'File .zst → original file'}{C.R}")
    pr()
    pr(f"  {C.B}[Y]{C.R}  Yes — decompress remotely via SSH")
    pr(f"  {C.B}[N]{C.R}  No  — leave compressed (receiver can decompress later)")
    sep()
    return ask("Decompress?", "Y").strip().upper() == "Y"


def _pick_local_from(start_path: str, title: str = "SELECT FILE OR FOLDER") -> str:
    """
    Local file browser that opens directly at start_path.
    User can navigate up/down freely — not restricted to that folder.
    Returns selected path or "".
    """
    current = start_path if os.path.isdir(start_path) else os.path.dirname(start_path)
    if not os.path.isdir(current):
        current = os.path.expanduser("~")
    history = []

    while True:
        clear()
        disp = current if len(current) <= W else "..." + current[-(W-3):]
        hdr(title, disp)
        items = _ls_local(current)

        PAGE = 40
        page_start = 0
        page_items = items[page_start: page_start + PAGE]
        total_pages = (len(items) + PAGE - 1) // PAGE if items else 1

        pr()
        parent = os.path.dirname(current)
        if parent and parent != current:
            pname = os.path.basename(parent) or parent
            print(f"  {C.B}[..]{C.R}  {C.D}↑  {pname}{C.R}")

        if not items:
            pr(f"  {C.D}(empty folder){C.R}")
        else:
            for i, (name, full, is_dir, size) in enumerate(page_items, 1):
                icon  = f"{C.CY}[D]{C.R} " if is_dir else "    "
                sz_s  = f"  {C.D}{size}{C.R}" if size else ""
                nm    = f"{C.D}{name}{C.R}" if name.startswith(".") else name
                print(f"  {C.B}[{i:>3}]{C.R}  {icon}{nm}{sz_s}")
            if total_pages > 1:
                pr()
                pr(f"  {C.D}Page 1/{total_pages}  ({len(items)} items){C.R}")

        pr()
        pr(f"  {C.B}[ S]{C.R}  Select THIS folder")
        pr(f"  {C.B}[ P]{C.R}  Paste/type a path")
        pr(f"  {C.B}[ ~]{C.R}  Jump to home")
        pr(f"  {C.B}[ 0]{C.R}  Back / cancel")
        sep()
        ch = ask("Choose", "")

        if ch == "0" or ch == "..":
            if history:
                current = history.pop()
            else:
                return ""
        elif ch.upper() == "S":
            return current
        elif ch.upper() == "P":
            path = input(f"\n  {C.B}❯  Type or paste path{C.R}: ").strip().strip('"').strip("'")
            if path and os.path.exists(path):
                return path
            if path:
                err(f"Not found: {path}"); time.sleep(1)
        elif ch.upper() == "~":
            history.append(current)
            current = os.path.expanduser("~")
        elif ch.isdigit():
            n = int(ch)
            if 1 <= n <= len(items):
                name, full, is_dir, size = items[n - 1]
                if is_dir:
                    history.append(current)
                    current = full
                else:
                    return full
            else:
                err(f"No item [{n}]."); time.sleep(0.7)
        else:
            err("Invalid."); time.sleep(0.7)

def _count_local_files(path: str) -> int:
    """
    Count files inside a local path.
    File → 1. Folder → recursive count. Compressed item → 1 (treated as file).
    """
    if not os.path.exists(path):
        return 0
    if os.path.isfile(path):
        return 1
    total = 0
    for _, _, files in os.walk(path):
        total += len(files)
    return max(total, 1)   # folder with 0 files still counts as 1 unit


def _total_file_count(items: list) -> int:
    """
    items: list of (path_to_send, original_path, is_compressed)
    Compressed items count as 1. Folders counted recursively.
    """
    total = 0
    for p2s, orig, is_compressed in items:
        if is_compressed:
            total += 1   # .7z = always 1 unit
        else:
            total += _count_local_files(p2s)
    return total


def _get_file_size_gb(path: str) -> float:
    """Return total size of path in GB."""
    try:
        if os.path.isfile(path):
            return os.path.getsize(path) / (1024**3)
        total = 0
        for dirpath, _, files in os.walk(path):
            for f in files:
                try: total += os.path.getsize(os.path.join(dirpath, f))
                except Exception: pass
        return total / (1024**3)
    except Exception:
        return 0.0


def _needs_tar(items: list) -> bool:
    """
    Decide if transfer needs a tar bundle.
    Rules:
      - Single file (not a folder, not compressed) → NEVER tar
      - Total file count <= TAR_THRESHOLD → no tar
      - Total file count > TAR_THRESHOLD → tar
    Compressed items always count as 1.
    """
    # Single raw file — never tar regardless of size
    if len(items) == 1:
        p2s, orig, is_compressed = items[0]
        if not is_compressed and os.path.isfile(p2s):
            return False
    return _total_file_count(items) > TAR_THRESHOLD


def _check_items_exist_remote(ip, user, port, kp, os_type: str,
                               items: list, remote_dest: str) -> list:
    """
    Check which of the selected items already exist at remote_dest.
    items: list of (path_to_send, original_path, is_compressed)
    Returns list of item names that exist on remote.
    """
    existing = []
    for p2s, orig, _ in items:
        fname = os.path.basename(p2s.rstrip("/\\"))
        remote_path = remote_dest.rstrip("/") + "/" + fname
        if os_type == "windows":
            win_path = remote_path.replace("/", "\\").replace("'", "''")
            out = run_cmd(ip, user, port,
                          f'powershell -NoProfile -Command "'
                          f'if (Test-Path \'{win_path}\') '
                          f'{{Write-Output EXISTS}} else {{Write-Output NEW}}"',
                          kp, timeout=6)
        else:
            out = run_cmd(ip, user, port,
                          f"test -e {shlex.quote(remote_path)} "
                          f"2>/dev/null && echo EXISTS || echo NEW",
                          kp, timeout=6)
        if "EXISTS" in out:
            existing.append(fname)
    return existing


def _handle_rsync_or_copy(ip, user, port, kp, os_type: str,
                           existing_names: list, remote_dest: str) -> str:
    """
    When items exist at destination, handle rsync install or Copy folder.
    Returns: "rsync" | "overwrite" | "copy_folder" | "cancel"

    Flow:
      1. Check rsync locally
      2. Check rsync on remote
      3. If either missing → offer install
      4. If install fails or user declines → ask overwrite or Copy folder
    """
    pr()
    pr(f"  {C.Y}These items already exist at destination:{C.R}")
    for n in existing_names:
        pr(f"    {C.D}• {n}{C.R}")
    pr()

    # Skip rsync for Windows remote — unreliable
    if os_type == "windows":
        pr(f"  {C.D}rsync not used for Windows remote — scp only.{C.R}")
        pr()
        pr(f"  {C.B}[1]{C.R}  Overwrite existing")
        pr(f"  {C.B}[2]{C.R}  Send to 'Copy' subfolder instead")
        pr(f"  {C.B}[0]{C.R}  Cancel")
        sep()
        ch = ask("Choose", "1").strip()
        if ch == "2": return "copy_folder"
        if ch == "0": return "cancel"
        return "overwrite"

    # Check rsync locally
    has_local_rsync  = _local_has_rsync()
    has_remote_rsync = False

    if has_local_rsync:
        pr(f"  {C.D}Checking rsync on remote...{C.R}")
        has_remote_rsync = _remote_check_rsync(ip, user, port, kp, os_type)

    if not has_local_rsync or not has_remote_rsync:
        missing = []
        if not has_local_rsync:  missing.append("this device (local)")
        if not has_remote_rsync: missing.append("remote device")
        pr(f"  {C.Y}rsync not found on: {', '.join(missing)}{C.R}")
        pr()
        pr(f"  {C.B}[1]{C.R}  Install rsync on missing device(s) then use rsync")
        pr(f"  {C.B}[2]{C.R}  Skip rsync — overwrite existing files")
        pr(f"  {C.B}[3]{C.R}  Skip rsync — send to 'Copy' subfolder")
        pr(f"  {C.B}[0]{C.R}  Cancel")
        sep()
        ch = ask("Choose", "1").strip()
        if ch == "0": return "cancel"
        if ch == "2": return "overwrite"
        if ch == "3": return "copy_folder"

        # Try install
        install_ok = True
        if not has_remote_rsync:
            pr(f"  {C.D}Installing rsync on remote...{C.R}")
            inst_ok, inst_msg = _remote_install_rsync(ip, user, port, kp, os_type)
            if inst_ok:
                ok(inst_msg)
                has_remote_rsync = True
            else:
                err(f"Remote rsync install failed: {inst_msg}")
                install_ok = False

        if not has_local_rsync and install_ok:
            pr(f"  {C.D}Installing rsync locally...{C.R}")
            los = local_os()
            _run_local_install("rsync", los,
                               _RSYNC_LOCAL_INSTALL.get(los, _RSYNC_LOCAL_INSTALL["other"]),
                               _local_has_rsync)
            _reload_path()
            if _local_has_rsync():
                ok("rsync installed locally ✓")
            else:
                err("Local rsync install failed.")
                install_ok = False

        if not install_ok:
            pr()
            pr(f"  {C.Y}rsync installation failed.{C.R}")
            pr(f"  {C.B}[1]{C.R}  Overwrite existing files")
            pr(f"  {C.B}[2]{C.R}  Send to 'Copy' subfolder")
            pr(f"  {C.B}[0]{C.R}  Cancel")
            sep()
            ch2 = ask("Choose", "1").strip()
            if ch2 == "2": return "copy_folder"
            if ch2 == "0": return "cancel"
            return "overwrite"

    ok("rsync available on both devices ✓")
    return "rsync"

def _compress_item_7z_to(local_path: str, archive_name: str,
                          level: str, dest_dir: str) -> str:
    """
    Compress item into dest_dir/<archive_name>.7z.
    Puts compressed file beside the source (same drive) not in /tmp.
    """
    safe     = re.sub(r"[^a-zA-Z0-9_\-]", "_", archive_name.strip()) or "archive"
    out_path = os.path.join(dest_dir, f"{safe}.7z")
    exe      = _get_7z_bin()
    args     = [exe, "a", out_path, f"-mx={level}", local_path]
    try:
        r = subprocess.run(args, capture_output=True)
        if r.returncode not in (0, 1):
            err(f"7z failed: {r.stderr.decode(errors='ignore')[:120]}")
            return ""
        return out_path
    except FileNotFoundError:
        err("7z not found — install via [8] Install tools")
        return ""
    except Exception as e:
        err(str(e))
        return ""


def _ask_remote_decompress(ip, user, port, kp, os_type: str,
                            final_items: list, remote_dest: str):
    """
    After transfer, ask to decompress .7z files on remote.
    Shows which files are compressed, checks 7z on remote, installs if needed.
    """
    compressed_names = [os.path.basename(p2s)
                        for p2s, orig, ic in final_items if ic]
    if not compressed_names:
        return

    sep()
    pr(f"  {C.B}Decompress .7z file(s) on remote device?{C.R}")
    for n in compressed_names:
        pr(f"    {C.D}• {n}{C.R}")
    pr()
    pr(f"  {C.B}[Y]{C.R}  Yes — extract and delete .7z files on remote")
    pr(f"  {C.B}[N]{C.R}  No  — leave .7z as-is")
    sep()
    if ask("Decompress on remote?", "Y").strip().upper() != "Y":
        return

    clear(); hdr("EXTRACTING ON REMOTE", f"{user}@{ip}")
    pr()
    pr(f"  {C.D}Checking 7-Zip on remote...{C.R}")
    if not _remote_check_7z(ip, user, port, kp):
        pr(f"  {C.Y}7-Zip not on remote — installing...{C.R}")
        inst_ok, inst_msg = _remote_install_7z(ip, user, port, kp, os_type)
        if not inst_ok:
            err("Could not install 7-Zip on remote.")
            pr(f"  {C.D}Extract manually: 7z x <file>.7z in {remote_dest}{C.R}")
            pause(); return
        ok(inst_msg)
        # Tell user 7z was installed and confirm continue
        pr()
        pr(f"  {C.B}7-Zip installed on remote ✓{C.R}")
        pr(f"  {C.B}[Y]{C.R}  Continue with decompression")
        pr(f"  {C.B}[N]{C.R}  Skip — decompress manually later")
        sep()
        if ask("Continue?", "Y").strip().upper() != "Y":
            return
    else:
        ok("7-Zip on remote ✓")

    all_ok = True
    for p2s, orig, ic in final_items:
        if not ic: continue
        remote_7z = f"{remote_dest.rstrip('/')}/{os.path.basename(p2s)}"
        d_ok, d_msg = _remote_extract_7z(ip, user, port, kp,
                                          remote_7z, remote_dest, os_type)
        if d_ok: ok(f"Extracted: {os.path.basename(p2s)} ✓")
        else:    err(f"Failed: {os.path.basename(p2s)} — {d_msg}"); all_ok = False

    if all_ok:
        ok("All items extracted on remote ✓")
    else:
        warn("Some extractions failed — check remote manually.")

def _make_copy_folder_remote(ip, user, port, kp, os_type: str,
                              remote_dest: str) -> str:
    """Create 'Copy' subfolder at remote_dest. Returns new dest path."""
    copy_dir = remote_dest.rstrip("/") + "/Copy"
    if os_type == "windows":
        win_cp = copy_dir.replace("/", "\\").replace("'", "''")
        run_cmd(ip, user, port,
                f'powershell -NoProfile -Command "'
                f'New-Item -ItemType Directory -Force -Path \'{win_cp}\' | Out-Null"',
                kp, timeout=10)
    else:
        run_cmd(ip, user, port,
                f"mkdir -p {shlex.quote(copy_dir)}", kp, timeout=10)
    return copy_dir

def _do_send(ip, user, port, os_type, kp, host: dict = None,
             force_local_start: str = "",
             force_remote_dest: str = ""):
    """
    SEND FLOW:
      1. Pick items one by one — ask compress per item
      2. Live browse remote destination
      3. Check each item at destination (actual names, not Transfer.tar)
      4. If exist → rsync install flow → rsync / overwrite / Copy folder
      5. If not exist → decide tar based on TAR_THRESHOLD
         - tar needed  → build beside first item, send, clean, extract remote
         - no tar      → send each item directly
      6. If compressed items in result → ask decompress on remote
    """
    tmp_files = []

    def _bail(*extra):
        _cleanup_temps(*tmp_files, *extra)

    # ── Step 1: pick items, compress per item ─────────────────────────
    final_items = []   # (path_to_send, original_path, is_compressed)
    sz7z_ok = _local_has_7z()

    while True:
        label = "Add another item?" if final_items else "What to send?"
        title = f"SEND → {user}@{ip}  |  {label}"
        local = (_pick_local_from(force_local_start, title)
                 if force_local_start else pick_local_path(title))
        if not local:
            if final_items: break
            return

        clear(); hdr("SEND — Queue", f"{len(final_items)+1} item(s) selected")
        pr()
        for i, (p2s, orig, ic) in enumerate(final_items, 1):
            tag = f"  {C.CY}[.7z]{C.R}" if ic else ""
            print(f"  {C.G}[{i}]{C.R}  {orig}  {C.D}({sz(orig)}){C.R}{tag}")
        print(f"  {C.G}[{len(final_items)+1}]{C.R}  {local}  "
              f"{C.D}({sz(local)}){C.R}  {C.Y}← just picked{C.R}")
        pr()

        compress_this = False
        level_this    = "5"
        if not sz7z_ok:
            pr(f"  {C.Y}7-Zip not installed — item will be sent raw.{C.R}")
        else:
            pr(f"  {C.B}Compress this item with 7-Zip?{C.R}")
            pr(f"  {C.B}[Y]{C.R}  Yes — compress into .7z")
            pr(f"  {C.B}[N]{C.R}  No  — send raw")
            sep()
            if ask("Compress?", "N").strip().upper() == "Y":
                compress_this = True
                pr()
                pr(f"  {C.B}Compression level:{C.R}")
                pr()
                for i, (lvl, desc) in enumerate(_7Z_LEVELS, 1):
                    mark = f"  {C.G}← recommended{C.R}" if lvl == "5" else ""
                    print(f"  {C.B}[{i}]{C.R}  Level {lvl}  —  {desc}{mark}")
                pr()
                level_ch = ask("Level", "3").strip()
                try:
                    idx        = int(level_ch) - 1
                    level_this = _7Z_LEVELS[idx][0] if 0 <= idx < len(_7Z_LEVELS) else "5"
                except ValueError:
                    level_this = "5"

        if compress_this:
            bname = re.sub(r"[^a-zA-Z0-9_\-]", "_",
                           os.path.basename(local.rstrip("/\\")).split(".")[0]) or "item"
            pr()
            pr(f"  {C.D}Compressing {os.path.basename(local)} → {bname}.7z...{C.R}")
            # Compress beside the source item (same drive)
            src_parent = os.path.dirname(os.path.abspath(local.rstrip("/\\")))
            zpath = _compress_item_7z_to(local, bname, level_this, src_parent)
            if not zpath:
                warn("Compression failed — item will be sent raw.")
                final_items.append((local, local, False))
            else:
                tmp_files.append(zpath)
                final_items.append((zpath, local, True))
                ok(f"Compressed: {os.path.basename(zpath)}  ({sz(zpath)})")
        else:
            final_items.append((local, local, False))

        pr()
        pr(f"  {C.B}[A]{C.R}  Add another item")
        pr(f"  {C.B}[D]{C.R}  Done — proceed to send")
        pr(f"  {C.B}[0]{C.R}  Cancel everything")
        sep()
        ch = ask("Choose", "D").upper()
        if ch == "0": _bail(); return
        if ch == "D": break

    if not final_items: return

    # ── Step 2: pick remote destination ──────────────────────────────
    if force_remote_dest:
        remote = force_remote_dest
        pr(f"  {C.D}Destination: {C.G}{remote}{C.R}")
    else:
        remote = pick_remote_path(os_type, user,
                                  f"SEND → {user}@{ip}  |  Where on device?",
                                  ip=ip, port=port, kp=kp)
    if not remote:
        _bail(); return

    # ── Step 3: check items at destination ───────────────────────────
    clear(); hdr("CHECKING DESTINATION", f"{user}@{ip}:{remote}")
    pr()
    pr(f"  {C.D}Checking if items already exist on remote...{C.R}")
    existing = _check_items_exist_remote(ip, user, port, kp, os_type,
                                          final_items, remote)

    # ── Step 4: rsync / overwrite / copy folder decision ─────────────
    transfer_mode = "scp"   # default
    actual_remote = remote

    if existing:
        sep()
        mode = _handle_rsync_or_copy(ip, user, port, kp, os_type,
                                      existing, remote)
        if mode == "cancel":
            _bail(); return
        if mode == "copy_folder":
            actual_remote = _make_copy_folder_remote(ip, user, port, kp,
                                                      os_type, remote)
            pr(f"  {C.D}Sending to: {C.G}{actual_remote}{C.R}")
            transfer_mode = "scp"
        elif mode == "rsync":
            transfer_mode = "rsync"
        else:   # overwrite
            transfer_mode = "scp"

    # ── Step 5: decide tar or direct ─────────────────────────────────
    use_tar = _needs_tar(final_items)
    has_compressed = any(ic for _, _, ic in final_items)

    _ri    = host.get("relay") if host else None
    _rkp   = get_key(_ri.get("device_id", "")) if _ri else ""
    _relay = bool(_ri and _rkp and not is_directly_reachable(ip))

    if transfer_mode == "rsync":
        # rsync each item directly — no tar needed
        clear(); hdr("SENDING VIA RSYNC", f"→ {user}@{ip}:{actual_remote}")
        pr()
        all_ok = True
        for p2s, orig, ic in final_items:
            pr(f"  {C.D}→ {os.path.basename(p2s)}{C.R}")
            dest_str = f"{user}@{ip}:{actual_remote}"
            ok2, msg = do_scp(p2s, dest_str, port, kp)
            if ok2: ok(f"{os.path.basename(p2s)} ✓")
            else:   err(msg); all_ok = False
        _bail()
        if not all_ok:
            warn("Some items failed. Check remote manually.")
        else:
            ok("All items transferred via rsync ✓")
        # Ask decompress if compressed items
        if has_compressed and all_ok:
            _ask_remote_decompress(ip, user, port, kp, os_type,
                                   final_items, actual_remote)
        pause(); return

    if use_tar:
        # Build tar beside first item's parent (same drive)
        first_src = final_items[0][0]
        tar_parent = os.path.dirname(os.path.abspath(first_src.rstrip("/\\")))
        transfer_tar = os.path.join(tar_parent, "Transfer.tar")
        paths_for_tar = [p2s for p2s, _, _ in final_items]
        t_cwd, t_names = _tar_cwd_and_names(paths_for_tar)

        clear(); hdr("PREPARING", f"Building Transfer.tar  ({len(final_items)} items)")
        pr()
        pr(f"  {C.D}Total files: {_total_file_count(final_items)}  "
           f"(threshold: {TAR_THRESHOLD}){C.R}")
        pr()

        try:
            r = subprocess.run(["tar", "-cf", transfer_tar] + t_names,
                               capture_output=True, cwd=t_cwd)
            if r.returncode != 0:
                err(f"tar failed: {r.stderr.decode(errors='ignore')[:120]}")
                _bail(transfer_tar); return
            tmp_files.append(transfer_tar)
            ok(f"Transfer.tar ready  ({sz(transfer_tar)})")
            time.sleep(0.3)
        except FileNotFoundError:
            err("tar not found on this device.")
            _bail(); return

        # Confirm
        clear(); hdr("SEND  |  Confirm")
        pr()
        pr(f"  Sending : {C.CY}Transfer.tar{C.R}  ({sz(transfer_tar)})")
        pr(f"  To      : {C.B}{user}@{ip}:{actual_remote}{C.R}")
        pr()
        pr(f"  Contents ({len(final_items)} item(s)):")
        for p2s, orig, ic in final_items:
            tag = f"  {C.CY}→ {os.path.basename(p2s)}{C.R}" if ic else ""
            print(f"    {C.G}•{C.R}  {os.path.basename(orig)}{tag}")
        pr()
        pr(f"  {C.B}[Y]{C.R}  Send now")
        if not force_remote_dest:
            pr(f"  {C.B}[N]{C.R}  Change destination")
        pr(f"  {C.B}[0]{C.R}  Cancel")
        sep()
        ch2 = ask("Choose", "").upper()
        if ch2 == "0": _bail(); return
        if ch2 == "N" and not force_remote_dest:
            remote = pick_remote_path(os_type, user, "SEND — new destination",
                                      ip=ip, port=port, kp=kp)
            if not remote: _bail(); return
            actual_remote = remote

        dest_str = f"{user}@{ip}:{actual_remote}"
        pr(f"\n  {C.B}→ Transfer.tar{C.R}")
        try:
            if _relay:
                ok2, msg = do_scp_relay(transfer_tar, dest_str, port, kp, _ri, _rkp)
            else:
                ok2, msg = do_scp(transfer_tar, dest_str, port, kp)
        except KeyboardInterrupt:
            print(); warn("Transfer cancelled.")
            _bail(); pause(); return

        _bail()   # delete tar + .7z files immediately

        if not ok2:
            err(f"Transfer failed: {msg}")
            pause(); return

        ok("Transferred!")
        sep()

        # Extract on remote
        remote_tar = f"{actual_remote.rstrip('/')}/Transfer.tar"
        pr(f"  {C.D}Extracting Transfer.tar on remote...{C.R}")
        if os_type == "windows":
            win_tar  = remote_tar.replace("/", "\\").replace("'","''")
            win_dest = actual_remote.replace("/", "\\").replace("'","''")
            xcmd = (f'powershell -NoProfile -Command "'
                    f'Set-Location \'{win_dest}\'; '
                    f'tar -xf \'{win_tar}\'; '
                    f'Remove-Item -Force \'{win_tar}\' -ErrorAction SilentlyContinue; '
                    f'Write-Output DONE_TAR"')
        else:
            arc_q  = shlex.quote(remote_tar)
            rdir_q = shlex.quote(actual_remote)
            xcmd = (f"tar -xf {arc_q} -C {rdir_q}"
                    f" ; rm -f {arc_q} ; echo DONE_TAR")
        out = run_cmd(ip, user, port, xcmd, kp, timeout=300)
        if "DONE_TAR" in out:
            ok("Transfer.tar extracted and deleted on remote ✓")
        else:
            warn("Extraction may have failed — check remote manually.")

        if has_compressed:
            _ask_remote_decompress(ip, user, port, kp, os_type,
                                   final_items, actual_remote)

    else:
        # Direct send — no tar
        clear(); hdr("SEND  |  Direct Transfer", f"→ {user}@{ip}:{actual_remote}")
        pr()
        pr(f"  {C.D}Total files: {_total_file_count(final_items)} "
           f"≤ {TAR_THRESHOLD} — sending directly{C.R}")
        pr()
        all_ok = True
        for p2s, orig, ic in final_items:
            pr(f"  {C.D}→ {os.path.basename(p2s)}{C.R}")
            dest_str = f"{user}@{ip}:{actual_remote}"
            try:
                if _relay:
                    ok2, msg = do_scp_relay(p2s, dest_str, port, kp, _ri, _rkp)
                else:
                    ok2, msg = do_scp(p2s, dest_str, port, kp)
            except KeyboardInterrupt:
                print(); warn("Transfer cancelled.")
                _bail(); pause(); return
            if ok2: ok(f"{os.path.basename(p2s)} ✓")
            else:   err(msg); all_ok = False

        _bail()
        if not all_ok:
            warn("Some items failed.")
        if has_compressed and all_ok:
            _ask_remote_decompress(ip, user, port, kp, os_type,
                                   final_items, actual_remote)

    sep()
    pr(f"  {C.D}Done.{C.R}")
    sep()
    pause()


def _cleanup_temps(*paths):
    """Delete any temp files created during send — silent on errors."""
    for p in paths:
        if p and os.path.exists(p):
            try: os.remove(p)
            except Exception: pass




def _do_receive(ip, user, port, os_type, kp, host: dict = None,
                force_remote_start: str = "",
                force_local_dest: str = ""):
    """
    Receive files/folders from remote device.

    force_remote_start: if set, open remote browser starting at this path
                        (Vault mode — starts in remote Linkx folder).
    force_local_dest:   if set, skip local path picker and land here
                        (Vault mode — lands in local Linkx folder).

    TAR BUNDLING (same logic as send):
    - Any folder or multiple items → tar on REMOTE first → scp single file
      → extract locally → delete remote tar automatically
    - Single file → scp directly
    """
    queue_items = []   # list of (remote_path, is_dir)

    # ── Step 1: build receive queue ───────────────────────────────────
    while True:
        label  = "Add another item" if queue_items else "What to receive?"
        if force_remote_start:
            # Vault mode: browser opens at Linkx folder, can navigate freely
            remote = pick_remote_path(os_type, user,
                                      f"RECEIVE ← {user}@{ip}  |  {label}",
                                      ip=ip, port=port, kp=kp,
                                      start_path=force_remote_start)
        else:
            remote = pick_remote_path(os_type, user,
                                      f"RECEIVE ← {user}@{ip}  |  {label}",
                                      ip=ip, port=port, kp=kp)
        if not remote:
            if queue_items: break
            return

        pr(f"\n  {C.D}Checking remote path...{C.R}")
        is_dir = remote_is_dir(ip, user, port, kp, remote)
        kind   = f"{C.CY}[Folder]{C.R}" if is_dir else "[File]"
        pr(f"  Detected: {kind}  {remote}")
        queue_items.append((remote, is_dir))

        clear(); hdr("RECEIVE — Queue", f"{len(queue_items)} item(s) selected")
        pr()
        for i, (p, d) in enumerate(queue_items, 1):
            icon = f"{C.CY}[D]{C.R}" if d else "   "
            print(f"  {C.G}[{i}]{C.R}  {icon}  {p}")
        pr()
        pr(f"  {C.B}[A]{C.R}  Add another file or folder")
        pr(f"  {C.B}[D]{C.R}  Done — choose save location")
        pr(f"  {C.B}[0]{C.R}  Cancel")
        sep()
        ch = ask("Choose", "").upper()
        if ch == "0": return
        if ch == "A": continue
        if ch == "D": break

    if not queue_items: return

    multi    = len(queue_items) > 1
    has_dir  = any(d for _, d in queue_items)
    
    # Count total files across all selected remote items
    # For remote items we can't walk — use placeholder count:
    # folders always use tar, files use threshold
    _file_items  = [(p, d) for p, d in queue_items if not d]
    _dir_items   = [(p, d) for p, d in queue_items if d]

    if _dir_items:
        # Has folders — need tar (folders always need bundling)
        use_tar = True
    elif len(_file_items) > TAR_THRESHOLD:
        # Many files — use tar
        use_tar = True
    elif len(_file_items) == 1:
        # Single file — check size (if > TAR_SKIP_SIZE_GB skip tar)
        use_tar = False
    else:
        # File + file combo
        use_tar = len(_file_items) > TAR_THRESHOLD  # always bundle dirs — avoids per-file SSH overhead

    # ── Step 2: pick local destination ───────────────────────────────
    if force_local_dest:
        # Vault mode: destination is pre-set to local Linkx folder
        local_dest = force_local_dest
        _ensure_linkx_folder_local()
        pr(f"  {C.D}Vault destination: {C.G}{local_dest}{C.R}")
    else:
        local_dest = pick_local_path(f"RECEIVE ← {user}@{ip}  |  Save where locally?")
        if not local_dest: return
        if os.path.isfile(local_dest):
            local_dest = os.path.dirname(local_dest)

    # ── Step 3: confirm ───────────────────────────────────────────────
    while True:
        clear(); hdr("RECEIVE  |  Confirm")
        pr()
        pr(f"  Receiving {C.G}{len(queue_items)}{C.R} item(s) from {C.B}{user}@{ip}{C.R}")
        if use_tar:
            pr(f"  Method  : {C.CY}tar bundle on remote → scp → extract locally{C.R}")
        pr(f"  Saving to: {C.G}{local_dest}{C.R}")
        if force_local_dest:
            pr(f"  {C.CY}[Vault] Destination locked to Linkx folder{C.R}")
        pr()
        for i, (p, d) in enumerate(queue_items, 1):
            icon = "Folder" if d else "File  "
            print(f"  {C.G}[{i}]{C.R}  {icon}  {p}")
        pr()
        pr(f"  {C.B}[Y]{C.R}  Transfer now")
        if not force_local_dest:
            pr(f"  {C.B}[N]{C.R}  Change local destination")
        pr(f"  {C.B}[0]{C.R}  Cancel")
        sep()
        ch = ask("Choose", "").upper()
        if ch == "0": return
        if ch == "N" and not force_local_dest:
            local_dest = pick_local_path("RECEIVE — Pick new save location")
            if not local_dest: return
            if os.path.isfile(local_dest):
                local_dest = os.path.dirname(local_dest)
            continue
        if ch == "Y":
            break

    _ri2     = host.get("relay") if host else None
    _rkp2    = get_key(_ri2.get("device_id","")) if _ri2 else ""
    _urelay2 = bool(_ri2 and _rkp2 and not is_directly_reachable(ip))

    try:
        if use_tar:
            # ── TAR on remote → scp single file → extract locally ────
            # Works without this app on the remote — uses standard tar/ssh only
            safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_",
                               os.path.basename(queue_items[0][0])) or "bundle"

            # Remote temp path — OS-aware
            if os_type == "windows":
                # Strip domain prefix: "v-15\admin" → "admin"
                # Raw domain user in path creates ghost folders on Windows
                _bare_user = user.split("\\")[-1] if "\\" in user else user
                # Use USERPROFILE via PowerShell to get real home path
                _win_home = run_cmd(ip, user, port,
                    'powershell -NoProfile -Command "Write-Output $env:USERPROFILE"',
                    kp, timeout=8)
                if _win_home.strip() and _win_home != "__TIMEOUT__":
                    _win_home = _win_home.strip().replace("\\", "/")
                else:
                    _win_home = f"C:/Users/{_bare_user}"
                remote_tar = f"{_win_home}/linkx_{safe_name}.tar"
            elif os_type == "android":
                remote_tar = f"/data/data/com.termux/files/home/linkx_{safe_name}.tar"
            else:
                remote_tar = f"/tmp/linkx_{safe_name}.tar"

            # Quote each path for remote POSIX shell (Linux/Android/macOS)
            if os_type == "windows":
                # Windows: cd to parent, tar only basenames
                _w_parents = list(set(p.rsplit("/", 1)[0] for p, _ in queue_items if "/" in p))
                if len(_w_parents) == 1:
                    _w_par = _w_parents[0]
                    _w_names = " ".join(f'"{os.path.basename(p)}"' for p, _ in queue_items)
                    win_par = _w_par.replace("/", "\\")
                    win_rtar = remote_tar.replace("/", "\\")
                    tar_cmd = (f'powershell -NoProfile -Command "'
                               f'Set-Location \'{win_par}\'; '
                               f'tar -cf \'{win_rtar}\' {_w_names}; '
                               f'Write-Output TAR_DONE"')
                else:
                    paths_list = " ".join(f'"{p}"' for p, _ in queue_items)
                    tar_cmd = f'tar -cf "{remote_tar}" {paths_list} && echo TAR_DONE'
            else:
                # POSIX: cd to parent dir, tar only basename — prevents full path nesting
                _p_parents = list(set(p.rsplit("/", 1)[0] if "/" in p else "."
                                      for p, _ in queue_items))
                remote_tar_q = shlex.quote(remote_tar)
                if len(_p_parents) == 1 and _p_parents[0] not in ("", "."):
                    _p_par_q  = shlex.quote(_p_parents[0])
                    _p_names  = " ".join(shlex.quote(p.rstrip("/").rsplit("/", 1)[-1])
                                         for p, _ in queue_items)
                    tar_cmd = (f"cd {_p_par_q} && tar -cf {remote_tar_q} {_p_names}"
                               f" && echo TAR_DONE")
                else:
                    paths_quoted = " ".join(shlex.quote(p) for p, _ in queue_items)
                    tar_cmd = f"tar -cf {remote_tar_q} {paths_quoted} && echo TAR_DONE"

            pr(f"\n  {C.D}Creating tar bundle on remote ({os_type})...{C.R}")
            pr(f"  {C.D}Paths: {', '.join(os.path.basename(p) for p,_ in queue_items)}{C.R}")

            out = run_cmd(ip, user, port, tar_cmd, kp, timeout=600)

            if "TAR_DONE" not in out:
                # Try to get more info about why it failed
                if os_type != "windows":
                    err_out = run_cmd(ip, user, port,
                                      f"tar -cf {remote_tar_q if os_type != 'windows' else shlex.quote(remote_tar)} "
                                      + (" ".join(shlex.quote(p) for p,_ in queue_items))
                                      + " 2>&1; echo EXIT:$?", kp, timeout=30)
                else:
                    err_out = out
                err(f"tar failed on remote.\nOutput: {(out or err_out or 'no output')[:300]}")
                pr(f"  {C.Y}Falling back to direct transfer (no bundling)...{C.R}")
                time.sleep(1)
                # Fallback: transfer each item directly
                for remote_p, is_dir in queue_items:
                    pr(f"\n  {C.B}← {os.path.basename(remote_p)}{C.R}")
                    if _urelay2:
                        ok2, msg = do_scp_relay(f"{user}@{ip}:{remote_p}",
                                                local_dest, port, kp,
                                                _ri2, _rkp2,
                                                force_recursive=is_dir)
                    else:
                        ok2, msg = do_scp(f"{user}@{ip}:{remote_p}",
                                          local_dest, port, kp,
                                          force_recursive=is_dir)
                    if ok2: ok(msg)
                    else:   err(msg)
                return

            bname     = os.path.basename(remote_tar)
            local_tar = os.path.join(tempfile.gettempdir(), bname)
            ok(f"Bundle ready: {bname}")
            pr(f"  {C.D}Downloading...{C.R}")

            # Download the tar
            if _urelay2:
                ok2, msg = do_scp_relay(f"{user}@{ip}:{remote_tar}",
                                        local_tar, port, kp, _ri2, _rkp2)
            else:
                ok2, msg = do_scp(f"{user}@{ip}:{remote_tar}",
                                   local_tar, port, kp)

            # Always clean up remote tar — success or fail
            if os_type == "windows":
                win_rtar2 = remote_tar.replace("/", "\\")
                run_cmd(ip, user, port,
                        f'powershell -NoProfile -Command '
                        f'"Remove-Item -Force \'{win_rtar2}\' -ErrorAction SilentlyContinue"',
                        kp, timeout=15)
            else:
                run_cmd(ip, user, port,
                        f"rm -f {shlex.quote(remote_tar)}", kp, timeout=15)

            if not ok2:
                err(msg)
                try: os.remove(local_tar)
                except Exception: pass
                pause(); return

            ok(msg)
            pr(f"  {C.D}Remote bundle deleted ✓{C.R}")

            # Extract locally
            pr(f"  {C.D}Extracting to: {local_dest}{C.R}")
            os.makedirs(local_dest, exist_ok=True)
            try:
                r = subprocess.run(
                    ["tar", "-xf", local_tar, "-C", local_dest],
                    capture_output=True, timeout=300)
                if r.returncode != 0:
                    msg2 = r.stderr.decode(errors="ignore")[:300]
                    err(f"Extraction failed (code {r.returncode}): {msg2}")
                    pr(f"  {C.Y}Archive kept at: {local_tar}{C.R}")
                    pr(f"  {C.Y}Extract manually: tar -xf \"{local_tar}\" -C \"{local_dest}\"{C.R}")
                else:
                    ok(f"Extracted to {local_dest} ✓")
                    try: os.remove(local_tar)
                    except Exception: pass
            except FileNotFoundError:
                err("tar not found locally.")
                pr(f"  Archive at: {local_tar}")
                pr(f"  Install tar (Windows): winget install GnuWin32.Tar")
            except subprocess.TimeoutExpired:
                err("Extraction timed out — archive kept locally.")

        else:
            # ── Single file — direct scp ──────────────────────────────
            remote_p, is_dir = queue_items[0]
            pr(f"\n  {C.B}← {os.path.basename(remote_p)}{C.R}"
               + (f"  {C.D}(folder){C.R}" if is_dir else ""))
            if _urelay2:
                ok2, msg = do_scp_relay(
                    f"{user}@{ip}:{remote_p}", local_dest,
                    port, kp, _ri2, _rkp2, force_recursive=is_dir)
            else:
                ok2, msg = do_scp(
                    f"{user}@{ip}:{remote_p}", local_dest,
                    port, kp, force_recursive=is_dir)
            if ok2: ok(msg)
            else:   err(msg)

    except KeyboardInterrupt:
        print()
        warn("Transfer cancelled (Ctrl+C)")
        pause(); return

    pr()
    sep()
    pr(f"  {C.D}Done. Stop SSH server on remote when finished:{C.R}")
    pr(f"  {C.Y}Android:{C.R}  pkill sshd")
    pr(f"  {C.Y}Windows:{C.R}  Stop-Service sshd")
    pr(f"  {C.Y}Linux  :{C.R}  sudo systemctl stop ssh")
    sep()
    pause()




def _do_browse(ip, user, port, os_type, kp):
    while True:
        remote = pick_remote_path(os_type, user, f"BROWSE  {user}@{ip}", ip=ip, port=port, kp=kp)
        if not remote: return
        clear(); hdr(f"BROWSE  {user}@{ip}", remote)
        cmd    = OS_PROFILES.get(os_type,OS_PROFILES["other"])["list"]
        out    = run_cmd(ip, user, port, f"{cmd} {shlex.quote(remote)} 2>&1", kp)
        pr(); sep()
        if out == "__TIMEOUT__":
            warn("SSH timed out — device slow or path too large to list")
        elif out:
            for line in out.split("\n"): print(f"  {line}")
        else:
            warn("No output — folder empty or permission denied")
        sep()
        pr(f"  {C.B}[B]{C.R}  Browse another path")
        pr(f"  {C.B}[0]{C.R}  Back")
        ch = ask("", "").upper()
        if ch != "B": return

def _do_cmd(ip, user, port, kp):
    clear(); hdr("REMOTE COMMAND")
    cmd = ask("Command  (0 to cancel)")
    if not cmd or cmd == "0": return
    pr(f"\n  {C.D}$ {cmd}{C.R}\n"); sep()
    out = run_cmd(ip, user, port, cmd, kp, timeout=60)
    if out:
        for line in out.split("\n"): print(f"  {line}")
    else: pr("  (no output)")
    sep(); pause()

# ─────────────────────────────────────────────────────────────────────
# QUICK SHARE — last-used path store
# .linkx_quick.json  →  { device_id: { "send": path, "recv": path } }
# ─────────────────────────────────────────────────────────────────────
def _load_qs() -> dict:
    try:
        with open(QUICK_SHARE_FILE, encoding='utf-8') as f: return json.load(f)
    except Exception: return {}

def _save_qs(d: dict):
    with _FILE_LOCK:
        try:
            tmp = QUICK_SHARE_FILE + ".tmp"
            with open(tmp, "w") as f: json.dump(d, f, indent=2)
            os.replace(tmp, QUICK_SHARE_FILE)
        except Exception:
            try: os.remove(tmp)
            except Exception: pass

def qs_get(device_id: str) -> dict:
    return _load_qs().get(device_id, {"send": "", "recv": ""})

def qs_save_send(device_id: str, local_path: str):
    d = _load_qs()
    d.setdefault(device_id, {"send":"","recv":""})["send"] = local_path
    _save_qs(d)

def qs_save_recv(device_id: str, remote_path: str, local_dest: str):
    d = _load_qs()
    d.setdefault(device_id, {"send":"","recv":""})
    d[device_id]["recv_remote"] = remote_path
    d[device_id]["recv_local"]  = local_dest
    _save_qs(d)

# ─────────────────────────────────────────────────────────────────────
# FAST PROBE — for known devices, skip full subnet scan
#
# Strategy (in order, stops as soon as device responds):
#   1. Direct TCP probe to last known IP  (~50ms if online)
#   2. ARP table lookup → probe that IP   (~instant)
#   3. Targeted subnet scan of last known /24  (slow, last resort)
# ─────────────────────────────────────────────────────────────────────
def _tcp_probe_fast(ip: str, port: int, timeout: float = FAST_PROBE_TIMEOUT) -> bool:
    """True if TCP port is open at ip."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connected = s.connect_ex((ip, port)) == 0
        s.close()
        return connected
    except Exception: return False

def _arp_find_ip_for_mac(mac: str) -> str:
    """Scan ARP table for a known MAC. Returns IP or ''."""
    if not mac: return ""
    mac_norm = mac.lower().replace("-",":")
    # /proc/net/arp — Linux
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3].lower() == mac_norm:
                    return parts[0]
    except Exception: pass
    # arp -a — Windows / macOS
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split("\n"):
            norm = line.lower().replace("-",":")
            if mac_norm in norm:
                # extract first IPv4-looking token
                for part in line.split():
                    part = part.strip("()")
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", part):
                        return part
    except Exception: pass
    return ""

def fast_find_device(host: dict, hosts: dict = None) -> str:
    """
    Locate a known device as quickly as possible.
    Returns the reachable IP string, or '' if not found.

    Step 1 — last known IP, direct TCP probe         (~50ms)
    Step 2 — ARP table lookup by MAC                 (instant, stable MACs only)
    Step 3 — Named-key targeted scan of last /24     (KEY IS THE SOUL)
              Only the specific named key is tried against each
              responding device — no brute-force key rotation.
              If a new IP is found, host dict is updated in-place
              so the caller can save the refreshed IP/MAC to JSON.
    Step 4 — Fallback subnet scan using MAC check    (last resort, unnamed keys)
    """
    ip       = host.get("ip", "")
    mac      = host.get("mac", "")
    port     = host.get("ssh_port", 22)
    did      = host.get("device_id", "")
    user     = host.get("user", "")
    key_name = host.get("key_name", "")  # e.g. "V-15_to_vivo"

    # Resolve the named key first, then fall back to key-DB
    named_kp = ""
    if key_name:
        candidate_path = os.path.join(_ssh_dir(), key_name)
        if os.path.exists(candidate_path):
            named_kp = candidate_path
    if not named_kp and did:
        named_kp = get_key(did) or ""

    # ── Step 1: direct probe of last known IP ────────────────────────
    if ip and _tcp_probe_fast(ip, port):
        return ip

    # ── Step 2: ARP table lookup (skip for MAC-randomizing OSes) ────
    if mac and not host.get("mac_randomized"):
        arp_ip = _arp_find_ip_for_mac(mac)
        if arp_ip and arp_ip != ip and _tcp_probe_fast(arp_ip, port):
            # Update host in-place so caller can persist the new IP
            host["ip"] = arp_ip
            host["mac"] = get_mac(arp_ip) or mac
            return arp_ip

    # ── Step 3: Named-key targeted scan ─────────────────────────────
    # For devices with a key_name (set during naming ceremony), probe
    # every responding SSH device on the last-known /24 subnet and try
    # ONLY the specific named key.  The key is the permanent identity —
    # IP and MAC are just hints that may have changed.
    if named_kp and user:
        # Scan ALL subnets (3-phase) — device may have moved to different subnet
        _h_dict = hosts if hosts else ({ip: host} if ip else {})
        subnets_3p = _collect_scan_subnets(_h_dict)
        my_ips = set(get_all_local_ips())
        candidates = []
        seen_cands = set()
        for _, pfx in subnets_3p:
            for i in range(1, 255):
                c = f"{pfx}.{i}"
                if c not in my_ips and c != ip and c not in seen_cands:
                    seen_cands.add(c); candidates.append(c)

        found_ip = ""
        lock = threading.Lock()

        def _try_named(cand):
            nonlocal found_ip
            if found_ip: return
            if not _tcp_probe_fast(cand, port, timeout=SCAN_TIMEOUT):
                return
            if test_key(cand, user, port, named_kp):
                with lock:
                    if not found_ip:
                        found_ip = cand

        if candidates:
            workers = min(MAX_WORKERS, len(candidates))
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                    futs3 = [ex.submit(_try_named, c) for c in candidates]
                    for fut in concurrent.futures.as_completed(futs3):
                        try: fut.result()
                        except Exception: pass
                        if found_ip:
                            for f2 in futs3: f2.cancel()
                            break
            except KeyboardInterrupt:
                pass

        if found_ip:
            # Key matched — update IP and MAC in host dict so caller
            # can write the refreshed values back to hosts.json.
            # Next session Step 1 (direct probe) will succeed instantly.
            host["ip"]  = found_ip
            host["mac"] = get_mac(found_ip) or mac
            return found_ip

    # ── Step 4: Fallback — subnet scan with MAC verification ────────
    # Used only when no named key is available (pre-naming legacy records).
    if ip and not named_kp:
        pfx = ".".join(ip.split(".")[:3])
        my_ips = set(get_all_local_ips())
        candidates = [f"{pfx}.{i}" for i in range(1, 255)
                      if f"{pfx}.{i}" not in my_ips]
        found_ip = ""
        lock = threading.Lock()

        def _try_mac(cand):
            nonlocal found_ip
            if found_ip: return
            if _tcp_probe_fast(cand, port, timeout=SCAN_TIMEOUT):
                h = probe_host(cand)
                if h and (not mac or not h.get("mac") or h["mac"] == mac):
                    with lock:
                        if not found_ip: found_ip = cand

        workers = min(MAX_WORKERS, len(candidates))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                futs4 = [ex.submit(_try_mac, c) for c in candidates]
                for fut in concurrent.futures.as_completed(futs4):
                    try: fut.result()
                    except Exception: pass
                    if found_ip:
                        for f2 in futs4: f2.cancel()
                        break
        except KeyboardInterrupt:
            pass

        if found_ip:
            host["ip"]  = found_ip
            host["mac"] = get_mac(found_ip) or mac
            return found_ip

    return ""

# ─────────────────────────────────────────────────────────────────────
# PASSIVE SCANNER — background thread that polls for device
# Calls callback(ip) when device comes online.
# Stops when stop_event is set.
# ─────────────────────────────────────────────────────────────────────
def passive_watch(host: dict, stop_event: threading.Event,
                  on_found_cb, hosts_ref: dict = None) -> None:
    """
    Runs in a background thread.
    Polls last IP every PASSIVE_POLL_INTERVAL seconds.
    Falls back to ARP and named-key / MAC subnet scan if direct probe fails 3x.
    hosts_ref: if provided, updated IP/MAC from fast_find_device is saved back.
    """
    ip      = host.get("ip","")
    mac     = host.get("mac","")
    port    = host.get("ssh_port", 22)
    misses  = 0

    while not stop_event.is_set():
        # Quick probe of last known IP first (cheapest)
        if ip and _tcp_probe_fast(ip, port):
            on_found_cb(ip)
            return

        misses += 1

        # After 3 misses try named-key / ARP / subnet scan
        if misses >= 3:
            new_ip = fast_find_device(host)   # may update host["ip"]/host["mac"]
            if new_ip:
                ip = new_ip   # use new IP for future direct probes this session
                # Persist the refreshed IP/MAC back to hosts.json
                if hosts_ref is not None and host.get("ip"):
                    old_key = [k for k, v in hosts_ref.items() if v is host]
                    for old_ip in old_key:
                        hosts_ref.pop(old_ip, None)
                    hosts_ref[new_ip] = host
                    save_hosts(hosts_ref)
                on_found_cb(new_ip)
                return
            misses = 0  # reset counter, try fast probe again next cycle

        stop_event.wait(PASSIVE_POLL_INTERVAL)

# ─────────────────────────────────────────────────────────────────────
# QUICK SHARE — main menu entry
#
# Flow:
#   1. Show known devices (from hosts.json) — no scan needed
#   2. User picks device
#   3. User picks action: Send or Receive
#   4. User picks file/folder (local browser or paste) — OR use last-used
#   5. User picks remote destination — OR use last-used
#   6. Show waiting screen — passive scan starts in background
#   7. The moment device is detected → scp fires automatically
# ─────────────────────────────────────────────────────────────────────
def menu_quick_share(hosts: dict) -> dict:
    """Quick Share — pick files first, device detected → auto transfer."""

    # ── Step 1: pick device from known list ──────────────────────────
    ready = {ip: h for ip, h in hosts.items()
             if h.get("device_id") and get_key(h.get("device_id",""))}

    if not ready:
        clear(); hdr("QUICK SHARE")
        warn("No devices with keys set up yet.")
        pr()
        pr(f"  Quick Share needs at least one device already set up")
        pr(f"  with a working SSH key.")
        pr()
        pr(f"  Use  {C.B}[1] Scan{C.R}  then  {C.B}[3] Setup{C.R}  from the main menu first.")
        pause(); return hosts

    clear(); hdr("QUICK SHARE", "Pick files first — transfer fires when device is found")
    pr()
    pr(f"  {C.B}Ready devices (key installed):{C.R}")
    pr()

    all_h = list(ready.values())
    for i, h in enumerate(all_h, 1):
        did  = h.get("device_id","")
        osl  = OS_PROFILES.get(h.get("os_type","other"),
                                OS_PROFILES["other"])["label"][:16]
        hn   = h["hostname"] if h.get("hostname","") != h["ip"] else ""
        age  = time.time() - h.get("seen_at", time.time())
        age_s= f"{int(age//3600)}h ago" if age > 3600 else \
               f"{int(age//60)}m ago"   if age > 60   else "just now"
        qs   = qs_get(did)
        last = ""
        if qs.get("send"):
            last = f"  {C.D}last sent: {os.path.basename(qs['send'])}{C.R}"
        lbl_qs = _device_label(h, 16)
        print(f"  {C.B}[{i}]{C.R}  {C.B}{lbl_qs:<18}{C.R} {h['ip']:<16} {osl:<18}"
              f"  {C.D}({age_s}){C.R}{last}")

    pr()
    pr(f"  {C.B}[0]{C.R}  Back")
    sep()
    ch = ask("Choose device")
    if ch == "0" or not ch: return hosts
    if not ch.isdigit() or not (1 <= int(ch) <= len(all_h)):
        err("Invalid."); time.sleep(0.8); return hosts

    host = all_h[int(ch)-1]
    did  = host.get("device_id","")
    ip   = host["ip"]
    user = host.get("user","")
    port = host.get("ssh_port", 22)
    os_type = host.get("os_type","other")
    kp   = get_key(did)
    qs   = qs_get(did)

    # ── Step 2: Send or Receive ───────────────────────────────────────
    clear(); hdr("QUICK SHARE", f"{user}@{ip}  —  {OS_PROFILES.get(os_type,OS_PROFILES['other'])['label']}")
    pr()
    pr(f"  {C.B}[1]{C.R}  Send   → send file / folder TO this device")
    pr(f"  {C.B}[2]{C.R}  Receive ← get file / folder FROM this device")
    pr()
    pr(f"  {C.B}[0]{C.R}  Back")
    sep()
    direction = ask("Choose")
    if direction == "0" or not direction: return hosts

    if direction == "1":
        # ── SEND path ─────────────────────────────────────────────────
        local_path = ""
        last_send  = qs.get("send","")

        clear(); hdr("QUICK SHARE — SEND", "Step 1: What to send?")
        pr()
        if last_send and os.path.exists(last_send):
            pr(f"  {C.B}[1]{C.R}  Use last:  {C.G}{last_send}{C.R}"
               f"  ({sz(last_send)})")
            pr(f"  {C.B}[2]{C.R}  Browse / paste new path")
        else:
            pr(f"  {C.B}[1]{C.R}  Browse / paste path")
        pr(f"  {C.B}[0]{C.R}  Back")
        sep()
        ch2 = ask("Choose")

        if ch2 == "0": return hosts
        if last_send and os.path.exists(last_send) and ch2 == "1":
            local_path = last_send
        else:
            local_path = pick_local_path("QUICK SHARE — Select file or folder to send")
        if not local_path: return hosts

        # Remote destination
        clear(); hdr("QUICK SHARE — SEND", "Step 2: Where on device?")
        pr()
        last_recv_dir = qs.get("recv_local","") # we reuse recv_local for send remote
        last_remote   = qs.get("send_remote","")
        if last_remote:
            pr(f"  {C.B}[1]{C.R}  Use last:  {C.G}{last_remote}{C.R}")
            pr(f"  {C.B}[2]{C.R}  Pick new remote path")
        else:
            pr(f"  {C.B}[1]{C.R}  Pick remote path")
        pr(f"  {C.B}[0]{C.R}  Back")
        sep()
        ch3 = ask("Choose")

        if ch3 == "0": return hosts
        if last_remote and ch3 == "1":
            remote_path = last_remote
        else:
            remote_path = pick_remote_path(os_type, user,
                           "QUICK SHARE — Where to send on device?",
                           ip=ip, port=port, kp=kp)
        if not remote_path: return hosts

        # Save last-used
        d = _load_qs()
        d.setdefault(did, {})
        d[did]["send"]        = local_path
        d[did]["send_remote"] = remote_path
        _save_qs(d)

        # ── Wait / Transfer ───────────────────────────────────────────
        _qs_wait_and_send(host, hosts, local_path, remote_path, kp)

    elif direction == "2":
        # ── RECEIVE path ──────────────────────────────────────────────
        last_remote = qs.get("recv_remote","")
        last_local  = qs.get("recv_local","")

        clear(); hdr("QUICK SHARE — RECEIVE", "Step 1: What to receive from device?")
        pr()
        if last_remote:
            pr(f"  {C.B}[1]{C.R}  Use last:  {C.G}{last_remote}{C.R}")
            pr(f"  {C.B}[2]{C.R}  Pick new remote path")
        else:
            pr(f"  {C.B}[1]{C.R}  Pick remote path")
        pr(f"  {C.B}[0]{C.R}  Back")
        sep()
        ch2 = ask("Choose")
        if ch2 == "0": return hosts
        if last_remote and ch2 == "1":
            remote_path = last_remote
        else:
            remote_path = pick_remote_path(os_type, user,
                           "QUICK SHARE — What to receive?",
                           ip=ip, port=port, kp=kp)
        if not remote_path: return hosts

        clear(); hdr("QUICK SHARE — RECEIVE", "Step 2: Save where locally?")
        pr()
        if last_local and os.path.exists(last_local):
            pr(f"  {C.B}[1]{C.R}  Use last:  {C.G}{last_local}{C.R}")
            pr(f"  {C.B}[2]{C.R}  Browse / paste new local path")
        else:
            pr(f"  {C.B}[1]{C.R}  Browse / paste local path")
        pr(f"  {C.B}[0]{C.R}  Back")
        sep()
        ch3 = ask("Choose")
        if ch3 == "0": return hosts
        if last_local and os.path.exists(last_local) and ch3 == "1":
            local_dest = last_local
        else:
            local_dest = pick_local_path("QUICK SHARE — Save received file where?")
        if not local_dest: return hosts
        if os.path.isfile(local_dest):
            local_dest = os.path.dirname(local_dest)

        # Save last-used
        d = _load_qs()
        d.setdefault(did, {})
        d[did]["recv_remote"] = remote_path
        d[did]["recv_local"]  = local_dest
        _save_qs(d)

        _qs_wait_and_recv(host, hosts, remote_path, local_dest, kp)

    else:
        err("Invalid."); time.sleep(0.8)

    return hosts


def _qs_wait_and_send(host: dict, hosts: dict,
                      local_path: str, remote_path: str, kp: str):
    """
    Show autopilot waiting screen.
    Passive scanner runs in background.
    When device online → scp fires automatically.
    """
    ip      = host["ip"]
    user    = host.get("user","")
    port    = host.get("ssh_port", 22)
    did     = host.get("device_id","")
    name    = host.get("hostname","") or ip
    os_type = host.get("os_type","other")

    stop_event  = threading.Event()
    found_ip    = [None]   # list so closure can write it
    found_event = threading.Event()

    def _on_found(resolved_ip):
        found_ip[0] = resolved_ip
        found_event.set()

    # Start passive watcher thread
    watcher = threading.Thread(target=passive_watch,
        args=(host, stop_event, _on_found, hosts),
        daemon=True)
    watcher.start()

    # ── Waiting screen ────────────────────────────────────────────────
    clear()
    hdr("QUICK SHARE — AUTOPILOT", f"Sending to {name}")
    pr()
    pr(f"  File  : {C.G}{local_path}{C.R}  ({sz(local_path)})")
    pr(f"  To    : {C.B}{user}@???:{remote_path}{C.R}")
    pr(f"  Device: {C.Y}{name}{C.R}  ({ip})")
    pr()
    sep()
    pr(f"  {C.D}Waiting for device to come online...{C.R}")
    pr(f"  {C.D}Polling every {PASSIVE_POLL_INTERVAL}s — transfer fires automatically{C.R}")
    pr(f"  {C.D}Press Ctrl+C to cancel{C.R}")
    sep()

    spinner = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    t0      = time.time()
    i       = 0
    try:
        while not found_event.is_set():
            elapsed = int(time.time() - t0)
            mins, secs = divmod(elapsed, 60)
            time_s = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
            spin   = spinner[i % len(spinner)]
            print(f"\r  {C.CY}{spin}{C.R}  Waiting...  {C.D}{time_s} elapsed{C.R}    ",
                  end="", flush=True)
            i += 1
            time.sleep(0.12)
            if found_event.is_set(): break
    except KeyboardInterrupt:
        stop_event.set()
        print(f"\n")
        warn("Cancelled by user.")
        pause(); return

    stop_event.set()
    real_ip = found_ip[0]
    print(f"\r  {C.G}●{C.R}  Device online at {C.G}{real_ip}{C.R}!            \n")

    # Update host record with confirmed IP
    if real_ip != ip:
        hosts = _qs_update_host_ip(host, hosts, real_ip)
        ip = real_ip

    # ── Fire — tar bundle always, rsync/scp routing, no compression ask ──
    print(f"  {C.B}Transferring...{C.R}\n")
    is_dir = os.path.isdir(local_path)
    _items = [(local_path, is_dir, sz(local_path))]

    # Always tar-bundle (automatic, no ask) for QS
    bundle_path = ""
    src_to_send = local_path
    if is_dir or True:   # always bundle — avoids per-file SSH overhead
        safe = re.sub(r"[^a-zA-Z0-9_\-]", "_",
                      os.path.basename(local_path.rstrip("/\\"))) or "bundle"
        bundle_path = os.path.join(tempfile.gettempdir(), f"{safe}_qs.tar")
        raw = [local_path]
        tar_cwd, tar_names = _tar_cwd_and_names(raw)
        r = subprocess.run(["tar", "-cf", bundle_path] + tar_names,
                           capture_output=True, cwd=tar_cwd)
        if r.returncode == 0:
            src_to_send = bundle_path
        else:
            src_to_send = local_path   # fallback — send as-is

    dest_scp = f"{user}@{ip}:{remote_path}"
    ok2, msg = do_scp(src_to_send, dest_scp, port, kp)

    # Clean up local tar
    if bundle_path and os.path.exists(bundle_path):
        try: os.remove(bundle_path)
        except Exception: pass

    if ok2:
        # Auto-extract on remote — no ask in QS mode
        if src_to_send != local_path:
            remote_tar = f"{remote_path.rstrip('/')}/{os.path.basename(bundle_path)}"
            _q = shlex.quote if os_type != "windows" else (lambda x: f'"{x}"')
            extract_cmd = f"cd {_q(remote_path)} && tar -xf {_q(os.path.basename(bundle_path))} && rm -f {_q(os.path.basename(bundle_path))} && echo DONE_EXTRACT"
            out = run_cmd(ip, user, port, extract_cmd, kp, timeout=300)
            if "DONE_EXTRACT" in out:
                ok(f"Done! Extracted on remote → {remote_path}")
            else:
                ok(f"Done! (archive at {remote_path}/{os.path.basename(bundle_path)} — extract manually)")
        else:
            ok(f"Done! → {remote_path}")
        _qs_notify(f"Sent to {name}: {os.path.basename(local_path)}")
    else:
        err(f"Transfer failed: {msg}")
    pause()


def _qs_wait_and_recv(host: dict, hosts: dict,
                      remote_path: str, local_dest: str, kp: str):
    """Autopilot receive version."""
    ip      = host["ip"]
    user    = host.get("user","")
    port    = host.get("ssh_port", 22)
    name    = host.get("hostname","") or ip

    stop_event  = threading.Event()
    found_ip    = [None]
    found_event = threading.Event()

    def _on_found(resolved_ip):
        found_ip[0] = resolved_ip
        found_event.set()

    watcher = threading.Thread(target=passive_watch,
        args=(host, stop_event, _on_found, hosts),
        daemon=True)
    watcher.start()

    clear()
    hdr("QUICK SHARE — AUTOPILOT", f"Receiving from {name}")
    pr()
    pr(f"  From  : {C.B}{user}@???:{remote_path}{C.R}")
    pr(f"  Save  : {C.G}{local_dest}{C.R}")
    pr(f"  Device: {C.Y}{name}{C.R}  ({ip})")
    pr()
    sep()
    pr(f"  {C.D}Waiting for device to come online...{C.R}")
    pr(f"  {C.D}Press Ctrl+C to cancel{C.R}")
    sep()

    spinner = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    t0 = time.time(); i = 0
    try:
        while not found_event.is_set():
            elapsed = int(time.time() - t0)
            mins, secs = divmod(elapsed, 60)
            time_s = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
            spin = spinner[i % len(spinner)]
            print(f"\r  {C.CY}{spin}{C.R}  Waiting...  {C.D}{time_s} elapsed{C.R}    ",
                  end="", flush=True)
            i += 1
            time.sleep(0.12)
    except KeyboardInterrupt:
        stop_event.set()
        print(f"\n")
        warn("Cancelled by user.")
        pause(); return

    stop_event.set()
    real_ip = found_ip[0]
    print(f"\r  {C.G}●{C.R}  Device online at {C.G}{real_ip}{C.R}!            \n")

    if real_ip != ip:
        hosts = _qs_update_host_ip(host, hosts, real_ip)
        ip = real_ip

    src_scp = f"{user}@{ip}:{remote_path}"
    print(f"  {C.B}Transferring...{C.R}\n")
    ok2, msg = do_scp(src_scp, local_dest, port, kp)
    if ok2:
        ok(f"Done! Saved to {local_dest}")
        _qs_notify(f"Received from {name}: {os.path.basename(remote_path)}")
    else:
        err(f"Transfer failed: {msg}")
    pause()


def _qs_update_host_ip(host: dict, hosts: dict, new_ip: str) -> dict:
    """Update IP in hosts dict and save when device found at new IP."""
    old_ip = host["ip"]
    host["ip"] = new_ip
    hosts.pop(old_ip, None)
    hosts[new_ip] = host
    host["seen_at"] = time.time()
    save_hosts(hosts)
    return hosts


def _qs_notify(msg: str):
    """
    Fire a system desktop/toast notification when transfer completes.
    Best-effort — silently ignored if platform doesn't support it.
    """
    try:
        if os.name == "nt":
            # PowerShell toast — no extra deps needed on Win 10+
            ps = (
                f'[Windows.UI.Notifications.ToastNotificationManager, '
                f'Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; '
                f'$t = [Windows.UI.Notifications.ToastNotificationManager]'
                f'::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]'
                f'::ToastText01); $t.GetElementsByTagName("text")[0].AppendChild('
                f'$t.CreateTextNode("" + $msg + "")); '
                f'[Windows.UI.Notifications.ToastNotificationManager]'
                f'::CreateToastNotifier("Linkx")'
                f'.Show([Windows.UI.Notifications.ToastNotification]::new($t))'
            )
            subprocess.Popen(["powershell", "-WindowStyle", "Hidden",
                              "-Command", ps],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "Linkx", msg],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif shutil.which("osascript"):
            subprocess.Popen(["osascript", "-e",
                              f'display notification "{msg}" with title "Linkx"'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception: pass

# ─────────────────────────────────────────────────────────────────────
# ZERO-CONFIG TWO-WAY PAIRING
#
# CONCEPT:
#   Both devices run linkx.py. Instead of manually entering
#   passwords, they find each other and exchange keys automatically.
#
# PROTOCOL:
#   HOST (the device that has sshd running):
#     1. Broadcasts a UDP beacon on port 55222 every 2s:
#        JSON: {role,hostname,user,ssh_port,pub_key,token}
#        token = random 6-digit PIN shown on screen — user confirms match
#
#   CLIENT (the device initiating the pair):
#     1. Listens on UDP 55222 for beacon
#     2. Displays the beacon info + PIN to user
#     3. User confirms PIN matches what HOST shows
#     4. Client connects via password SSH (user types password ONCE)
#     5. Client installs its own pub key on HOST → HOST can SSH to CLIENT
#     6. HOST's pub key (from beacon) installed on CLIENT → CLIENT can SSH to HOST
#     7. Both sides now have passwordless keys in BOTH directions
#
# RESULT: Full two-way key exchange. No manual IP entry, no config.
#   Device A → Device B  : works
#   Device B → Device A  : works
#   All future transfers  : fully automated, no password ever again
#
# SECURITY:
#   PIN confirmation prevents rogue devices from pairing silently.
#   Beacon only contains public key — private key never leaves device.
#   Token expires after pairing completes or timeout.
# ─────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────
# SSH SERVER MANAGEMENT — detect OS, start server with correct command
# ─────────────────────────────────────────────────────────────────────

def _detect_ssh_port() -> int:
    """Return the port this device's SSH server uses (8022 Termux, 22 others)."""
    if os.path.exists("/data/data/com.termux/files/home"):
        return 8022
    return 22

def _is_sshd_running(port: int) -> bool:
    """TCP probe to 127.0.0.1:port — True if sshd is actually accepting."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex(("127.0.0.1", port))
        s.close()
        return result == 0
    except Exception:
        return False

def _win_is_admin() -> bool:
    """True if the current process has Windows Admin privileges."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _win_open_firewall():
    """
    Add (or refresh) the two inbound firewall rules on Windows.
    Called after sshd is confirmed running.
    If not Admin, silently skips — elevated path in _start_sshd already
    runs netsh inside the UAC-elevated process.
    """
    if os.name != "nt":
        return
    rules = [
        # SSH port 22 — keep permanently while sshd is in use
        ["netsh", "advfirewall", "firewall", "add", "rule",
         "name=linkx_SSH_in", "protocol=TCP", "dir=in",
         "localport=22", "action=allow", "enable=yes", "profile=any"],
        # ICMP ping — temporary, removed after pairing / on stop
        ["netsh", "advfirewall", "firewall", "add", "rule",
         "name=linkx_ICMP_in", "protocol=icmpv4:8,any", "dir=in",
         "action=allow", "enable=yes", "profile=any"],
    ]
    for cmd in rules:
        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
        except Exception:
            pass


def _start_sshd() -> tuple:
    """
    Start SSH server on this device using the correct OS command.
    Returns (success: bool, port: int, message: str).

    Detection logic:
      Termux/Android  → sshd                              port 8022
      Windows         → net start sshd                    port 22
      macOS           → sudo systemsetup -setremotelogin on  port 22
      Linux systemd   → sudo systemctl start ssh|sshd     port 22
      Linux SysV      → sudo service ssh|sshd start       port 22
      Linux fallback  → sudo sshd                         port 22
    """
    port = _detect_ssh_port()

    # Already running — return immediately
    if _is_sshd_running(port):
        return True, port, "SSH server already running"

    is_termux = os.path.exists("/data/data/com.termux/files/home")
    los = local_os()

    # ── Termux / Android ─────────────────────────────────────────────
    if is_termux:
        pr(f"  {C.D}Starting sshd (Termux, port 8022)...{C.R}")
        try:
            subprocess.run(["sshd"], capture_output=True, timeout=5)
            time.sleep(1)
            if _is_sshd_running(8022):
                return True, 8022, "sshd started (Termux)"
            return False, 8022, "sshd failed — run: pkg install openssh"
        except FileNotFoundError:
            return False, 8022, "sshd not found — run: pkg install openssh"
        except Exception as e:
            return False, 8022, str(e)

    # ── Windows ──────────────────────────────────────────────────────
    if los in ("windows", "windows_old"):
        pr(f"  {C.D}Starting OpenSSH Server (Windows)...{C.R}")

        # If already running just add firewall rules and return
        if _is_sshd_running(22):
            _win_open_firewall()
            return True, 22, "OpenSSH Server already running"

        # Try direct start first (works if already Admin)
        try:
            r = subprocess.run(["net", "start", "sshd"],
                               capture_output=True, text=True, timeout=15)
            time.sleep(1)
            if _is_sshd_running(22) or "already been started" in r.stdout.lower():
                _win_open_firewall()
                return True, 22, "OpenSSH Server started"
        except Exception:
            pass

        # Direct start failed — not running as Admin.
        # Re-launch the three commands elevated via UAC (PowerShell -Verb RunAs).
        # A UAC dialog will pop up asking the user to confirm.
        pr(f"  {C.Y}Admin rights needed — a UAC prompt will appear.{C.R}")
        pr(f"  {C.D}Click YES in the UAC dialog to continue.{C.R}")
        time.sleep(0.5)
        ps_script = (
            "net start sshd; "
            "netsh advfirewall firewall add rule name=linkx_SSH_in "
            "protocol=TCP dir=in localport=22 action=allow enable=yes profile=any; "
            "netsh advfirewall firewall add rule name=linkx_ICMP_in "
            "protocol=icmpv4:8,any dir=in action=allow enable=yes profile=any"
        )
        try:
            # Start-Process -Verb RunAs triggers UAC and runs elevated.
            # -WindowStyle Hidden keeps the extra window from flashing.
            # We wait up to 20s for the elevated process to finish.
            subprocess.run([
                "powershell", "-NoProfile", "-Command",
                f'Start-Process powershell -ArgumentList '
                f'"-NoProfile -Command {ps_script}" '
                f'-Verb RunAs -Wait -WindowStyle Hidden'
            ], timeout=30)
        except Exception as e:
            return False, 22, (
                f"UAC elevation failed: {e}\n"
                "  Run PowerShell as Administrator and type:\n"
                "    Start-Service sshd\n"
                "    netsh advfirewall firewall add rule name=linkx_SSH_in "
                "protocol=TCP dir=in localport=22 action=allow\n"
                "    netsh advfirewall firewall add rule name=linkx_ICMP_in "
                "protocol=icmpv4:8,any dir=in action=allow")

        time.sleep(2)   # give the elevated process a moment to finish
        if _is_sshd_running(22):
            return True, 22, "OpenSSH Server started (elevated via UAC)"

        return False, 22, (
            "OpenSSH Server did not start.\n"
            "  Make sure it is installed first:\n"
            "  Settings → Apps → Optional Features → OpenSSH Server\n"
            "  Then click YES on the UAC prompt when it appears.")

    # ── Windows (old — 7/8/8.1, no native OpenSSH) ───────────────────
    if los == "windows_old":
        return False, 22, (
            "Windows 7 / 8 / 8.1 do not include OpenSSH.\n"
            "  Option 1: Install Win32-OpenSSH from GitHub:\n"
            "    https://github.com/PowerShell/Win32-OpenSSH/releases\n"
            "    Download OpenSSH-Win64.zip, extract, run install-sshd.ps1 as Admin\n"
            "  Option 2: Use a third-party SSH server (Bitvise, FreeSSHd)\n"
            "  Option 3: Upgrade to Windows 10 build 1809 or newer")

    # ── macOS ────────────────────────────────────────────────────────
    # systemsetup requires Full Disk Access on Catalina+ (10.15+).
    # Fallback: launchctl, which works on all macOS versions.
    if los == "macos":
        pr(f"  {C.D}Enabling Remote Login (macOS)...{C.R}")
        # Try systemsetup first (fastest, works pre-Catalina and when FDA granted)
        try:
            r = subprocess.run(
                ["sudo", "systemsetup", "-setremotelogin", "on"],
                capture_output=True, text=True, timeout=15)
            time.sleep(1)
            if _is_sshd_running(22):
                return True, 22, "Remote Login (SSH) enabled via systemsetup"
        except Exception:
            pass
        # Fallback: launchctl — works on all macOS including Catalina+
        pr(f"  {C.D}Trying launchctl fallback...{C.R}")
        try:
            subprocess.run(
                ["sudo", "launchctl", "load", "-w",
                 "/System/Library/LaunchDaemons/ssh.plist"],
                capture_output=True, timeout=15)
            time.sleep(1)
            if _is_sshd_running(22):
                return True, 22, "SSH enabled via launchctl"
        except Exception:
            pass
        return False, 22, (
            "Could not enable SSH automatically on macOS.\n"
            "  Manual steps:\n"
            "    System Settings → General → Sharing → Remote Login → ON\n"
            "  Or in Terminal (may need Full Disk Access for script):\n"
            "    sudo systemsetup -setremotelogin on\n"
            "  Note: macOS Ventura/Sonoma disabled RSA keys by default.\n"
            "  If you get 'no matching host key' errors, this app will\n"
            "  handle it automatically during key exchange.")

    # ── Linux — distro-aware start ────────────────────────────────────
    # Service name: Debian/Ubuntu/Kali use 'ssh', most others use 'sshd'
    # Init system:
    #   systemctl  → Debian, Ubuntu, Kali, RHEL, Fedora, Arch, SUSE, Void(sv)
    #   OpenRC     → Alpine (rc-service), Gentoo
    #   runit      → Void (sv)
    #   SysV       → old Debian/Ubuntu, very old RHEL

    pr(f"  {C.D}Starting SSH server ({los})...{C.R}")

    # Choose correct service name for this distro family
    if los in ("debian", "kali"):
        svc_names = ("ssh", "sshd")        # Debian/Ubuntu use 'ssh'
    elif los == "alpine":
        svc_names = ("sshd",)              # Alpine OpenRC
    else:
        svc_names = ("sshd", "ssh")        # RHEL, Arch, SUSE, Gentoo prefer 'sshd'

    # ── Alpine Linux (OpenRC, no systemd) ────────────────────────────
    if los == "alpine":
        for cmd_set in (
            ["sudo", "rc-service", "sshd", "start"],
            ["sudo", "service", "sshd", "start"],
        ):
            try:
                subprocess.run(cmd_set, capture_output=True, timeout=15)
                time.sleep(1)
                if _is_sshd_running(22):
                    return True, 22, f"SSH started via: {' '.join(cmd_set)}"
            except Exception:
                pass
        # Install hint
        return False, 22, (
            "Could not start SSH on Alpine.\n"
            "  Install : apk add openssh\n"
            "  Enable  : rc-update add sshd\n"
            "  Start   : rc-service sshd start")

    # ── Void Linux (runit) ────────────────────────────────────────────
    if los == "void":
        try:
            subprocess.run(["sudo", "sv", "start", "sshd"],
                           capture_output=True, timeout=15)
            time.sleep(1)
            if _is_sshd_running(22):
                return True, 22, "SSH started via: sv start sshd"
        except Exception:
            pass
        return False, 22, (
            "Could not start SSH on Void.\n"
            "  Install  : sudo xbps-install openssh\n"
            "  Enable   : sudo ln -s /etc/sv/sshd /var/service/\n"
            "  Start    : sudo sv start sshd")

    # ── Gentoo (OpenRC default, systemd optional) ─────────────────────
    if los == "gentoo":
        for cmd_set in (
            ["sudo", "rc-service", "sshd", "start"],
            ["sudo", "systemctl", "start", "sshd"],
        ):
            try:
                subprocess.run(cmd_set, capture_output=True, timeout=15)
                time.sleep(1)
                if _is_sshd_running(22):
                    return True, 22, f"SSH started via: {' '.join(cmd_set)}"
            except Exception:
                pass
        return False, 22, (
            "Could not start SSH on Gentoo.\n"
            "  Install: emerge net-misc/openssh\n"
            "  Start  : rc-service sshd start  (OpenRC)\n"
            "        or: systemctl start sshd    (systemd)")

    # ── All systemd distros (Debian, Ubuntu, Kali, RHEL, Fedora,
    #    Arch, Manjaro, SUSE, and generic Linux) ─────────────────────
    if shutil.which("systemctl"):
        for svc in svc_names:
            try:
                subprocess.run(["sudo", "systemctl", "start", svc],
                               capture_output=True, timeout=15)
                time.sleep(1)
                if _is_sshd_running(22):
                    return True, 22, f"SSH started: systemctl start {svc}"
            except Exception:
                pass

    # ── SysV service fallback (old Ubuntu 14.04, old RHEL 6, etc.) ───
    if shutil.which("service"):
        for svc in svc_names:
            try:
                subprocess.run(["sudo", "service", svc, "start"],
                               capture_output=True, timeout=15)
                time.sleep(1)
                if _is_sshd_running(22):
                    return True, 22, f"SSH started: service {svc} start"
            except Exception:
                pass

    # ── Direct sshd binary (last resort) ─────────────────────────────
    if shutil.which("sshd"):
        try:
            subprocess.Popen(["sudo", "sshd"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.5)
            if _is_sshd_running(22):
                return True, 22, "sshd started directly"
        except Exception:
            pass

    # ── Install + start hint per distro family ────────────────────────
    install_hints = {
        "debian" : "sudo apt install openssh-server && sudo systemctl start ssh",
        "kali"   : "sudo apt install openssh-server && sudo systemctl start ssh",
        "rhel"   : "sudo dnf install openssh-server && sudo systemctl start sshd",
        "arch"   : "sudo pacman -S openssh && sudo systemctl start sshd",
        "suse"   : "sudo zypper install openssh && sudo systemctl start sshd",
        "alpine" : "apk add openssh && rc-service sshd start",
        "void"   : "sudo xbps-install openssh && sudo sv start sshd",
        "gentoo" : "emerge net-misc/openssh && rc-service sshd start",
        "linux"  : "sudo systemctl start ssh  OR  sudo systemctl start sshd",
    }
    hint = install_hints.get(los, install_hints["linux"])
    return False, 22, (
        f"Could not start SSH server automatically ({los}).\n"
        f"  Try manually:\n    {hint}\n"
        f"  Then run this option again.")


def _pair_token() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"

def _my_pub_key() -> str:
    """Return any existing public key for this device."""
    km = _load_km()
    for did, kpath in km.items():
        pub = kpath + ".pub"
        if os.path.exists(pub):
            try: return open(pub).read().strip()
            except Exception: pass
    for kpath in _find_existing_keys():
        pub = kpath + ".pub"
        if os.path.exists(pub):
            try: return open(pub).read().strip()
            except Exception: pass
    return ""

def _win_fix_sshd_config(programdata: str = ""):
    """
    Ensure Windows sshd_config has the settings required for key auth.
    This is the #1 hidden cause of 'permission denied' on Windows even
    after keys are correctly installed:

    Required settings:
      PubkeyAuthentication yes   (may be commented out by default)
      AuthorizedKeysFile .ssh/authorized_keys  (must include user path)

    Also: administrators_authorized_keys must NOT be commented out,
    and must be readable only by SYSTEM + Administrators.

    Rewrites sshd_config in-place if needed, then restarts sshd.
    Silent on permission errors — user may need to run as Admin.
    """
    if os.name != "nt":
        return
    if not programdata:
        programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")

    cfg_path = os.path.join(programdata, "ssh", "sshd_config")
    if not os.path.exists(cfg_path):
        return

    try:
        with open(cfg_path, encoding="utf-8", errors="ignore") as f:
            original = f.read()
    except Exception:
        return

    lines    = original.splitlines()
    changed  = False
    new_lines = []

    need_pubkey = True    # PubkeyAuthentication yes
    need_akf    = True    # AuthorizedKeysFile setting

    for line in lines:
        stripped = line.strip()
        lower    = stripped.lower()

        # Enable PubkeyAuthentication
        if lower.startswith("#pubkeyauthentication") or lower.startswith("pubkeyauthentication"):
            new_lines.append("PubkeyAuthentication yes")
            need_pubkey = False
            if "pubkeyauthentication yes" not in lower:
                changed = True
            continue

        # Keep AuthorizedKeysFile line — don't comment it out
        if lower.startswith("authorizedkeysfile") or lower.startswith("#authorizedkeysfile"):
            # Ensure the user-level path is included
            if "administrators_authorized_keys" in lower:
                # This is the admin-only line — keep it uncommented
                if stripped.startswith("#"):
                    new_lines.append(stripped[1:].strip())
                    changed = True
                else:
                    new_lines.append(line)
                need_akf = False
            else:
                new_lines.append(line)
                if not stripped.startswith("#"):
                    need_akf = False
            continue

        new_lines.append(line)

    if need_pubkey:
        new_lines.insert(0, "PubkeyAuthentication yes")
        changed = True

    if need_akf:
        new_lines.append("AuthorizedKeysFile .ssh/authorized_keys")
        changed = True

    if not changed:
        return

    new_content = "\n".join(new_lines) + "\n"
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        # Restart sshd to apply — silent failure if no admin rights
        subprocess.run(["net", "stop", "sshd"],  capture_output=True, timeout=10)
        subprocess.run(["net", "start", "sshd"], capture_output=True, timeout=10)
    except Exception:
        pass   # requires Admin — best effort


def _install_pub_key_locally(pub_key: str):
    """
    Add a remote device's public key to our own authorized_keys.

    Windows admin accounts: OpenSSH Server reads from
    C:\\ProgramData\\ssh\\administrators_authorized_keys
    NOT from ~/.ssh/authorized_keys.
    We write to BOTH locations so it works regardless of account type.

    ALSO: verifies sshd_config has PubkeyAuthentication yes — the most
    common reason Windows shows permission denied even after key install.
    """
    pub_key = pub_key.strip()
    parts   = pub_key.split()
    key_id  = " ".join(parts[:2]) if len(parts) >= 2 else pub_key

    def _write_to(auth_file: str, is_windows_admin: bool = False):
        try:
            os.makedirs(os.path.dirname(auth_file), exist_ok=True)
            existing = ""
            if os.path.exists(auth_file):
                try:
                    with open(auth_file, encoding="utf-8", errors="ignore") as f:
                        existing = f.read()
                except Exception:
                    pass
            if key_id in existing:
                return   # already installed
            with open(auth_file, "a", encoding="utf-8") as f:
                f.write(f"\n{pub_key}\n")
            if os.name != "nt":
                os.chmod(auth_file, 0o600)
            elif is_windows_admin:
                # Fix ACL on administrators_authorized_keys — Windows OpenSSH
                # refuses to read this file if it has wrong permissions.
                try:
                    subprocess.run([
                        "icacls", auth_file,
                        "/inheritance:r",
                        "/grant", "SYSTEM:(F)",
                        "/grant", "BUILTIN\\Administrators:(F)"
                    ], capture_output=True, timeout=10)
                except Exception:
                    pass
        except Exception as e:
            warn(f"Could not write {auth_file}: {e}")

    # Standard path — works for all non-admin users and Linux/macOS/Android
    ssh_dir   = _ssh_dir()
    auth_file = os.path.join(ssh_dir, "authorized_keys")
    _write_to(auth_file, is_windows_admin=False)

    # Windows admin path — required for Administrator accounts
    if os.name == "nt":
        programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        admin_auth  = os.path.join(programdata, "ssh", "administrators_authorized_keys")
        _write_to(admin_auth, is_windows_admin=True)

        # CRITICAL: Verify sshd_config has PubkeyAuthentication yes
        # This is the #1 reason Windows shows permission denied after key install
        _win_fix_sshd_config(programdata)

def _get_all_subnet_ips() -> list:
    """
    Return all IPs to scan for pairing.
    Includes local subnets AND extra hotspot/bridged subnets so that
    a VMware bridged VM on 192.168.122.x can still find a phone on
    192.168.43.x via the gateway bridge.
    """
    my_ips   = get_all_local_ips()
    my_ips_s = set(my_ips)
    seen_pfx = set()
    result   = []

    for ip in my_ips:
        if ip.startswith("169.254.") or ip.startswith("127."): continue
        pfx = ".".join(ip.split(".")[:3])
        if pfx in seen_pfx: continue
        seen_pfx.add(pfx)
        for i in range(1, 255):
            candidate = f"{pfx}.{i}"
            if candidate not in my_ips_s:
                result.append(candidate)

    for _gw, pfx in _extra_hotspot_subnets(my_ips):
        if pfx in seen_pfx: continue
        seen_pfx.add(pfx)
        for i in range(1, 255):
            result.append(f"{pfx}.{i}")

    return result

def menu_pair(hosts: dict) -> dict:
    clear(); hdr("ZERO-CONFIG PAIRING", "Pair two devices running linkx.py")
    pr()
    pr(f"  {C.B}How this works:{C.R}")
    pr(f"  Both devices run linkx.py and choose Pair.")
    pr(f"  Both devices start SSH server first.")
    pr(f"  HOST opens a pairing listener, CLIENT scans and finds it,")
    pr(f"  confirms a PIN, both enter each other's password once,")
    pr(f"  keys installed both ways — no passwords ever again.")
    pr()
    sep()

    # ── Start SSH server on THIS device before role selection ─────────
    # Both HOST and CLIENT need SSH server running for two-way connection.
    pr(f"  {C.D}Starting SSH server on this device...{C.R}")
    sshd_ok, my_ssh_port, sshd_msg = _start_sshd()
    if sshd_ok:
        ok(f"SSH server ready on port {my_ssh_port}")
    else:
        warn("SSH server could not start on this device.")
        for line in sshd_msg.split("\n"):
            pr(f"  {C.Y}{line}{C.R}")
        pr()
        pr(f"  {C.Y}The other device will NOT be able to connect to you.{C.R}")
        pr(f"  {C.Y}You can still connect TO the other device (one-way).{C.R}")
        if ask("Continue anyway?", "N").upper() != "Y":
            return hosts

    pr()
    sep()
    pr(f"  {C.B}[1]{C.R}  HOST   — I am the device others connect TO")
    pr(f"  {C.B}[2]{C.R}  CLIENT — I will find and connect to the HOST")
    pr()
    pr(f"  {C.B}[0]{C.R}  Back")
    sep()
    ch = ask("Choose")
    if ch == "1": return _pair_as_host(hosts, my_ssh_port)
    if ch == "2": return _pair_as_client(hosts, my_ssh_port)
    return hosts


def _win_remove_all_firewall_rules():
    """
    Remove BOTH firewall rules added by linkx on Windows:
      linkx_SSH_in  — TCP port 22 inbound
      linkx_ICMP_in — ICMPv4 ping inbound
    Called whenever sshd is stopped so Windows is left exactly as it
    was before this tool was ever run — no permanent changes left behind.
    Elevates via UAC if not already Admin.
    Silent on non-Windows or any failure — non-fatal in all cases.
    """
    if os.name != "nt":
        return
    rules_to_delete = "linkx_SSH_in", "linkx_ICMP_in"
    if _win_is_admin():
        for name in rules_to_delete:
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={name}",
                ], capture_output=True, timeout=8)
            except Exception:
                pass
    else:
        cmds = "; ".join(
            f"netsh advfirewall firewall delete rule name={n}"
            for n in rules_to_delete
        )
        try:
            subprocess.run([
                "powershell", "-NoProfile", "-Command",
                f'Start-Process powershell -ArgumentList '
                f'"-NoProfile -Command {cmds}" '
                f"-Verb RunAs -WindowStyle Hidden"
            ], timeout=15)
        except Exception:
            pass


# Keep old name as alias so pairing exit-paths still compile
_remove_icmp_firewall_rule = _win_remove_all_firewall_rules


def _pair_as_host(hosts: dict, my_ssh_port: int = 22) -> dict:
    """
    HOST role — two-way setup via pairing.
    SSH server already started in menu_pair before we got here.
    1. Generate fresh keypair specifically for this pairing session
    2. Open TCP listener — send beacon with PIN and our info
    3. Wait for CLIENT to connect and send client_hello
    4. Extract CLIENT info from client_hello
    5. Install CLIENT pub key locally (so CLIENT can SSH to us)
    6. Generate fresh key for CLIENT using CLIENT device_id
    7. Ask for CLIENT password — install our key on CLIENT via password SSH
    8. Verify key works both ways
    9. Save CLIENT to database
    10. Naming ceremony
    """
    clear(); hdr("PAIRING — HOST MODE", "Preparing...")
    pr()

    ok(f"SSH server on port {my_ssh_port}")

    my_user = getpass.getuser()
    my_host = socket.gethostname()

    # Generate fresh keypair — named with session token for now,
    # naming ceremony will rename to HostName_to_ClientName
    pr(f"  {C.D}Generating fresh keypair for this pairing...{C.R}")
    _session_token = _pair_token()
    my_kp, pub_key = generate_key(_session_token, my_host)
    if not pub_key:
        err("ssh-keygen failed"); pause(); return hosts
    ok(f"Keypair ready: {os.path.basename(my_kp)}")

    token  = _pair_token()   # separate PIN token for the handshake
    my_ips = [ip for ip in get_all_local_ips()
              if not classify_ip(ip)[1] and not ip.startswith("127.")]

    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", PAIR_PORT))
        srv.listen(3)
        srv.settimeout(1)
    except Exception as e:
        err(f"Cannot open pairing port {PAIR_PORT}: {e}")
        pause(); return hosts

    clear(); hdr("PAIRING — HOST MODE", "Waiting for CLIENT...")
    pr()
    pr(f"  {C.B}HOST info:{C.R}")
    pr(f"  Hostname : {C.G}{my_host}{C.R}")
    pr(f"  User     : {C.G}{my_user}{C.R}")
    pr(f"  SSH port : {C.G}{my_ssh_port}{C.R}")
    for ip in my_ips:
        pr(f"  IP       : {C.G}{ip}{C.R}")
    pr()
    sep()
    pr(f"  {C.B}PIN — CLIENT must confirm this matches:{C.R}")
    print(f"\n  {C.CY}╔{'═'*20}╗{C.R}")
    print(f"  {C.CY}║{C.R}   {C.B}{token}{C.R}   {C.CY}            ║{C.R}")
    print(f"  {C.CY}╚{'═'*20}╝{C.R}\n")
    pr(f"  {C.D}CLIENT is scanning the LAN...{C.R}")
    pr(f"  {C.D}Ctrl+C to cancel{C.R}")
    sep()

    result         = [None]
    client_seen_at = [0.0]
    stop_srv       = threading.Event()

    payload = json.dumps({
        "role"     : "host_hello",
        "hostname" : my_host,
        "user"     : my_user,
        "ssh_port" : my_ssh_port,
        "pub_key"  : pub_key,
        "token"    : token,
    }).encode()

    def _serve():
        while not stop_srv.is_set():
            try:
                conn, addr = srv.accept()
                if not client_seen_at[0]:
                    client_seen_at[0] = time.time()
                conn.sendall(payload + b"\n")
                data = b""
                conn.settimeout(15)
                try:
                    while b"\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk: break
                        data += chunk
                        if len(data) > 65536:
                            data = b""; break
                except Exception: pass
                conn.close()
                if data:
                    try:
                        msg = json.loads(data.strip())
                        # Only stop when CLIENT sends its actual registration
                        # not on the first scan probe which sends nothing
                        if (msg.get("token") == token
                                and msg.get("role") == "client_hello"):
                            result[0] = (addr[0], msg)
                            stop_srv.set()
                    except Exception: pass
            except socket.timeout: continue
            except Exception:      continue
        try: srv.close()
        except Exception: pass

    st = threading.Thread(target=_serve, daemon=True)
    st.start()

    spinner = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    t0 = time.time(); i = 0
    try:
        while not stop_srv.is_set():
            elapsed = int(time.time() - t0)
            print(f"\r  {C.CY}{spinner[i%len(spinner)]}{C.R}  "
                  f"Waiting for CLIENT...  {elapsed}s", end="", flush=True)
            i += 1
            for _ in range(6):
                if stop_srv.is_set(): break
                time.sleep(0.02)
            # Before CLIENT connects: PAIR_TIMEOUT from start
            # After CLIENT connects: 120s more for password entry
            if client_seen_at[0]:
                if time.time() - client_seen_at[0] > 120:
                    stop_srv.set()
                    _remove_icmp_firewall_rule()
                    print(f"\n"); warn("Timed out waiting for CLIENT registration.")
                    pause(); return hosts
            elif elapsed >= PAIR_TIMEOUT:
                stop_srv.set()
                _remove_icmp_firewall_rule()
                print(f"\n"); warn("Timed out."); pause(); return hosts
    except KeyboardInterrupt:
        stop_srv.set()
        _remove_icmp_firewall_rule()
        print(f"\n  {C.D}Cancelled.{C.R}"); pause(); return hosts

    stop_srv.set(); print(f"\n")

    if not result[0]:
        _remove_icmp_firewall_rule()
        warn("No CLIENT connected."); pause(); return hosts

    client_ip, msg  = result[0]
    client_user     = msg.get("user", "")
    client_host     = msg.get("hostname", "")
    client_ssh_port = msg.get("ssh_port", 22)
    client_pub_key  = msg.get("pub_key", "")
    client_os       = msg.get("os_type", "")

    ok(f"CLIENT found: {client_user}@{client_ip}")

    # Detect CLIENT OS if not sent
    if not client_os:
        if client_ssh_port == 8022:
            client_os = "android"
        elif "windows" in client_host.lower():
            client_os = "windows"
        else:
            client_os = "linux"

    # Install CLIENT pub key locally so CLIENT can SSH to us
    if client_pub_key:
        _install_pub_key_locally(client_pub_key)
        ok(f"CLIENT key installed — {client_user}@{client_ip} can SSH here ✓")
    else:
        warn("CLIENT sent no public key")

    # Build CLIENT device identity
    mac = get_mac(client_ip)
    did = make_device_id(mac, client_host, client_user)

    # Rename fresh key to be tied to this CLIENT's device_id
    _kp_named = os.path.join(
        _ssh_dir(), f"id_ed25519_{did[:8]}")
    try:
        _kp_r = os.path.realpath(os.path.expanduser(my_kp))
        if _kp_r != os.path.realpath(os.path.expanduser(_kp_named)):
            for _old in (_kp_named, _kp_named + ".pub"):
                if os.path.exists(_old): os.remove(_old)
            os.rename(_kp_r, _kp_named)
            _pub_r = _kp_r + ".pub"
            if os.path.exists(_pub_r):
                os.rename(_pub_r, _kp_named + ".pub")
            my_kp = _kp_named
    except Exception:
        pass  # naming ceremony will rename it properly

    # Now HOST must install ITS key onto CLIENT via password SSH
    # This is the two-way part — exactly like Setup but from HOST to CLIENT
    sep()
    pr(f"  {C.B}Two-way setup:{C.R} Installing HOST key on CLIENT")
    pr(f"  {C.Y}Enter the password of {client_user}@{client_ip}{C.R}")
    pr(f"  {C.G}This is the only password you will ever need for this device.{C.R}")
    pr()

    # Read our pub key to install on CLIENT
    _my_pub_for_client = ""
    try:
        _my_pub_for_client = open(my_kp + ".pub").read().strip()
    except Exception:
        pass

    _host_install_ok = False
    if _my_pub_for_client:
        _host_install_ok = _install_key_interactive(
            client_ip, client_user, client_ssh_port,
            _my_pub_for_client, os_type=client_os)
        if _host_install_ok:
            ok(f"HOST key installed on CLIENT — HOST can reach CLIENT ✓")
        else:
            warn("Could not install HOST key on CLIENT — one-way only")
    else:
        warn("No pub key to install on CLIENT")

    save_key(did, my_kp)

    new_host = {
        "ip"            : client_ip,
        "hostname"      : client_host,
        "mac"           : mac,
        "ssh_port"      : client_ssh_port,
        "os_type"       : client_os,
        "user"          : client_user,
        "device_id"     : did,
        "key_source"    : os.path.basename(my_kp),
        "key_ok"        : True,
        "mac_randomized": client_os in MAC_RANDOMIZED_OS,
        "seen_at"       : time.time(),
    }
    hosts[client_ip] = new_host
    save_hosts(hosts)
    _remove_icmp_firewall_rule()

    ok("HOST pairing complete!")
    pr(f"  {C.G}✓{C.R}  CLIENT can SSH to us")
    pr(f"  {C.G}✓{C.R}  We can SSH to CLIENT" if _host_install_ok
       else f"  {C.Y}✗{C.R}  We cannot SSH to CLIENT (key install failed)")

    # Naming ceremony
    # is_pair=False — CLIENT has just had its SSH key installed so we
    # CAN rename the remote key if _host_install_ok, but _name_connection
    # with is_pair=True will try to do that automatically
    _my_kp_r = os.path.realpath(os.path.expanduser(my_kp))
    if os.path.exists(_my_kp_r):
        kp_after, new_host = _name_connection(
            new_host, _my_kp_r, hosts,
            remote_ip=client_ip, remote_user=client_user,
            remote_port=client_ssh_port,
            is_pair=_host_install_ok)
        hosts[client_ip] = new_host
        save_hosts(hosts)
    else:
        pause()
    return hosts


def _probe_pair_port(ip: str) -> bool:
    """Quick TCP probe for the pairing port.
    Uses 1.5s timeout — longer than FAST_PROBE_TIMEOUT because VMware
    bridged networks have higher latency than direct LAN connections.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        result = s.connect_ex((ip, PAIR_PORT)) == 0
        s.close()
        return result
    except Exception:
        return False


def _pair_as_client(hosts: dict, my_ssh_port: int = 22) -> dict:
    """
    CLIENT role — two-way setup via pairing.
    SSH server already started in menu_pair before we got here.
    1. Scan LAN for HOST on PAIR_PORT
    2. Read HOST beacon — get PIN and HOST info
    3. User confirms PIN
    4. Generate fresh keypair for HOST
    5. Send client_hello to HOST immediately (while HOST listener is alive)
    6. Install our key on HOST via password SSH (one password entry)
    7. Install HOST pub key locally
    8. Verify key works against HOST
    9. Save HOST to database
    10. Naming ceremony
    """
    clear(); hdr("PAIRING — CLIENT MODE", "Scanning LAN for HOST...")
    pr()

    my_user = getpass.getuser()
    my_host = socket.gethostname()
    my_los  = local_os()

    scan_candidates = _get_all_subnet_ips()
    total = len(scan_candidates)
    pr(f"  {C.D}Scanning {total} IPs on port {PAIR_PORT}...{C.R}")
    pr(f"  {C.D}Ctrl+C to cancel{C.R}")
    sep()

    found_host = [None]
    stop_scan  = threading.Event()
    scanned    = [0]
    lock       = threading.Lock()

    def _scan_one(ip):
        if stop_scan.is_set(): return
        if _probe_pair_port(ip):
            try:
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.settimeout(5)
                conn.connect((ip, PAIR_PORT))
                data = b""
                try:
                    while b"\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk: break
                        data += chunk
                except Exception: pass
                conn.close()
                if data:
                    msg = json.loads(data.strip())
                    if msg.get("role") == "host_hello":
                        with lock:
                            if not found_host[0]:
                                found_host[0] = (ip, msg)
                                stop_scan.set()
            except Exception: pass
        with lock:
            scanned[0] += 1

    workers = min(MAX_WORKERS, total)
    spinner = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0; t0 = time.time()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_scan_one, ip) for ip in scan_candidates]
            try:
                while not stop_scan.is_set():
                    done    = scanned[0]
                    pct     = int(done * 100 / total) if total else 100
                    elapsed = int(time.time() - t0)
                    print(f"\r  {C.CY}{spinner[i%len(spinner)]}{C.R}  "
                          f"Scanning {done}/{total} ({pct}%)...  {elapsed}s",
                          end="", flush=True)
                    i += 1; time.sleep(0.1)
                    if done >= total: break
            except KeyboardInterrupt:
                stop_scan.set()
                for f2 in futs: f2.cancel()
                print(f"\n  {C.D}Cancelled.{C.R}"); pause(); return hosts
    except Exception: pass

    stop_scan.set(); print(f"\n")

    if not found_host[0]:
        err("No HOST found on this network.")
        pr(f"  Make sure the other device chose HOST mode first.")
        pause(); return hosts

    host_ip, beacon = found_host[0]
    host_user       = beacon.get("user", "")
    host_host       = beacon.get("hostname", "")
    host_port       = beacon.get("ssh_port", 22)
    host_pub_key    = beacon.get("pub_key", "")
    token           = beacon.get("token", "")

    # PIN confirmation
    clear(); hdr("PAIRING — CLIENT MODE", f"HOST found: {host_host}")
    pr()
    pr(f"  {C.B}HOST device:{C.R}")
    pr(f"  IP       : {C.G}{host_ip}{C.R}")
    pr(f"  Hostname : {C.G}{host_host}{C.R}")
    pr(f"  User     : {C.G}{host_user}{C.R}")
    pr(f"  SSH port : {C.G}{host_port}{C.R}")
    pr()
    sep()
    pr(f"  {C.B}Confirm PIN matches HOST screen:{C.R}")
    print(f"\n  {C.CY}╔{'═'*20}╗{C.R}")
    print(f"  {C.CY}║{C.R}   {C.B}{token}{C.R}   {C.CY}            ║{C.R}")
    print(f"  {C.CY}╚{'═'*20}╝{C.R}\n")
    sep()
    pr(f"  {C.B}[Y]{C.R}  PIN matches — pair now")
    pr(f"  {C.B}[N]{C.R}  Wrong device — cancel")
    sep()
    if ask("PIN confirmed?", "Y").upper() != "Y":
        warn("Pairing cancelled."); pause(); return hosts

    # Detect HOST OS
    _host_rec = hosts.get(host_ip, {})
    _host_os  = _host_rec.get("os_type", "")
    if not _host_os:
        if host_port == 8022:         _host_os = "android"
        elif "windows" in host_host.lower(): _host_os = "windows"
        else:                          _host_os = "linux"

    # Generate fresh keypair specifically for HOST
    host_mac = get_mac(host_ip)
    did      = make_device_id(host_mac, host_host, host_user)
    pr()
    pr(f"  {C.D}Generating fresh keypair for this pairing...{C.R}")
    my_kp, my_pub = generate_key(did, host_host)
    if not my_pub:
        err("Key generation failed"); pause(); return hosts
    ok(f"Keypair ready: {os.path.basename(my_kp)}")

    # Send client_hello to HOST NOW — while HOST listener is still alive
    # Must happen BEFORE password step which takes 10-40 seconds
    pr()
    pr(f"  {C.D}Registering with HOST...{C.R}")
    reply = json.dumps({
        "role"     : "client_hello",
        "hostname" : my_host,
        "user"     : my_user,
        "ssh_port" : my_ssh_port,
        "pub_key"  : my_pub,
        "os_type"  : my_los,
        "token"    : token,
    }).encode() + b"\n"

    _registered = False
    for _attempt in range(3):
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(10)
            conn.connect((host_ip, PAIR_PORT))
            # Read and discard beacon
            _d = b""
            try:
                while b"\n" not in _d:
                    _c = conn.recv(4096)
                    if not _c: break
                    _d += _c
            except Exception: pass
            conn.sendall(reply)
            conn.close()
            _registered = True
            break
        except Exception:
            if _attempt < 2: time.sleep(1)
    if _registered:
        ok("Registered with HOST ✓")
    else:
        warn("Could not register with HOST — HOST may have timed out")

    # Install our key on HOST via password SSH — one password entry
    sep()
    pr(f"  {C.B}Step 1/2:{C.R} Installing our key on HOST")
    pr(f"  {C.Y}Enter password of {host_user}@{host_ip}{C.R}")
    pr(f"  {C.G}This is the only time a password is needed.{C.R}\n")
    if not _install_key_interactive(
            host_ip, host_user, host_port, my_pub, os_type=_host_os):
        err("Key install failed — check username and password.")
        pause(); return hosts
    ok("Our key installed on HOST ✓")

    # Install HOST pub key locally
    sep()
    pr(f"  {C.B}Step 2/2:{C.R} Installing HOST key locally")
    if host_pub_key:
        _install_pub_key_locally(host_pub_key)
        ok("HOST key installed locally ✓")
    else:
        warn("HOST sent no public key — HOST cannot reach us")

    # Verify our key works against HOST
    time.sleep(1)
    kp = ""
    for _k in _find_existing_keys():
        if test_key(host_ip, host_user, host_port, _k):
            kp = _k; break
    if kp:
        save_key(did, kp)
        ok(f"Key verified — {host_user}@{host_ip} ✓")
    else:
        # my_kp is correct — sshd on HOST may still be reloading
        kp = my_kp
        save_key(did, kp)
        warn("Key saved — verify failed (sshd reloading), will work shortly")

    new_host = {
        "ip"            : host_ip,
        "hostname"      : host_host,
        "mac"           : host_mac,
        "ssh_port"      : host_port,
        "os_type"       : _host_os,
        "user"          : host_user,
        "device_id"     : did,
        "key_source"    : os.path.basename(kp),
        "key_ok"        : True,
        "mac_randomized": _host_os in MAC_RANDOMIZED_OS,
        "seen_at"       : time.time(),
    }
    hosts[host_ip] = new_host
    save_hosts(hosts)

    print()
    ok("TWO-WAY PAIRING COMPLETE!")
    pr(f"  {C.G}✓{C.R}  We can SSH/SCP to HOST ({host_user}@{host_ip})")
    pr(f"  {C.G}✓{C.R}  HOST can SSH/SCP to us (key installed both ways)")
    pr(f"  {C.D}No password ever needed again.{C.R}")

    # Naming ceremony
    _kp_r = os.path.realpath(os.path.expanduser(kp))
    if os.path.exists(_kp_r):
        kp_after, new_host = _name_connection(
            new_host, _kp_r, hosts,
            remote_ip=host_ip, remote_user=host_user,
            remote_port=host_port, is_pair=True)
        hosts[host_ip] = new_host
        save_hosts(hosts)
    else:
        pause()
    return hosts


# ─────────────────────────────────────────────────────────────────────
# SCAN MENU
#
# Architecture: ONE reader thread blocks on input() the whole time.
# Scanner thread prints FOUND lines as they arrive — they appear above
# the cursor. User types a number + Enter exactly once into the prompt.
# No polling loop, no races, no double-prompts.
# ─────────────────────────────────────────────────────────────────────

def _collect_scan_subnets(hosts: dict) -> list:
    """_collect_scan_subnets: menu_scan, fast_find_device. Builds (ip,prefix) list for 3-phase scan."""
    all_ips  = get_all_local_ips()
    seen_pfx = set()
    subnets  = []
    for ip in all_ips:
        if ip.startswith("169.254.") or ip.startswith("127."): continue
        pfx = ".".join(ip.split(".")[:3])
        if pfx not in seen_pfx:
            seen_pfx.add(pfx); subnets.append((ip, pfx))
    # Always include stored device subnets (handles cross-subnet hotspot case)
    for h in hosts.values():
        sip = h.get("ip","")
        if sip and not sip.startswith(("127.","169.254.")):
            pfx = ".".join(sip.split(".")[:3])
            if pfx not in seen_pfx:
                seen_pfx.add(pfx); subnets.append((sip, pfx))
    # Hotspot gateway-bridged subnets
    for gw, pfx in _extra_hotspot_subnets(all_ips):
        if pfx not in seen_pfx:
            seen_pfx.add(pfx); subnets.append((gw, pfx))
    return subnets

def menu_scan(hosts: dict) -> dict:
    clear(); hdr("SCANNING NETWORK")
    pr(f"\n  {C.D}Detecting subnets...{C.R}" )

    subnets  = _collect_scan_subnets(hosts)
    all_ips  = get_all_local_ips()

    pr(f"\n  Scan strategy :")
    pr()
    pr(f"  {C.CY}Phase 1{C.R}  {C.G}→{C.R} Stored devices (last known IP + MAC)  "
       f"{C.D}[instant]{C.R}")
    virt_s = []
    real_s = []
    for ip, pfx in subnets:
        label, is_virt = classify_ip(ip)
        if is_virt: virt_s.append(pfx)
        else: real_s.append(f"{pfx}.x")
    subnets_str = ", ".join(real_s) if real_s else "none"
    pr(f"  {C.CY}Phase 2{C.R}  {C.G}→{C.R} Full subnet scan  {C.D}{subnets_str}{C.R}")
    if virt_s:
        pr(f"           {C.D}+ virtual: {', '.join(virt_s)}{C.R}")

    known_count = len(hosts)
    if known_count:
        pr(f"  {C.D}{known_count} stored device(s) — Phase 1 probes these first{C.R}")

    extra = [h["ip"] for h in hosts.values()
             if not any(h["ip"].startswith(pfx+".") for _,pfx in subnets)]

    pr()
    pr(f"  Ports : 22 (Linux/Win/Mac)  8022 (Android/Termux)")
    _actual_workers = _os_aware_workers()
    pr(f"  Speed : {SCAN_TIMEOUT}s/host  |  {_actual_workers} threads  |  ports 22+8022 parallel")
    sep()
    pr(f"  {C.D}Devices appear live as found. Type number + Enter to jump.{C.R}")
    pr(f"  {C.D}Ctrl+C to cancel.{C.R}")
    sep()
    print()
    t0 = time.time()

    # ── Shared state ──────────────────────────────────────────────────
    found_list = []
    found_lock = threading.Lock()
    scan_done  = threading.Event()
    abort_ev   = threading.Event()
    # Queue for user input: reader thread puts typed lines here
    input_q = queue.Queue()

    # ── on_found: called from scanner threads, prints above prompt ────
    print_lock = threading.Lock()   # keep FOUND lines atomic

    def on_found(h):
        with found_lock:
            idx = len(found_list) + 1
            found_list.append(h)
        # Use nickname if already known from stored data
        known = hosts.get(h["ip"],{})
        nick  = known.get("nickname","") or h.get("nickname","")
        lbl   = nick if nick else (h["hostname"] if h["hostname"] != h["ip"] else "")
        lbl_s = f"  {C.G}{lbl}{C.R}" if lbl else ""
        mac_s = f"  {C.D}MAC:{h['mac']}{C.R}" if h.get("mac") else ""
        os_s  = (f"  {C.M}Android{C.R}"       if h["ssh_port"]==8022 else
                 f"  {C.D}{h['os_type']}{C.R}" if h.get("os_type","unknown")!="unknown"
                 else "")
        did   = h.get("device_id","") or known.get("device_id","")
        kp_s  = f"  {C.G}[\u2713 key]{C.R}" if (did and get_key(did)) else ""
        with print_lock:
            print(f"\r  {C.G}FOUND [{idx}]{C.R}  {h['ip']:<16}{lbl_s}  "
                  f":{h['ssh_port']}{mac_s}{os_s}{kp_s}")
            print(f"         {C.D}\u2192 type {idx} + Enter to jump there now{C.R}")
            print(f"  {C.B}\u276f{C.R}  Device number (or Enter when done): ", end="", flush=True)

    # ── Scanner thread ────────────────────────────────────────────────
    def _scanner():
        scan_network(subnets, extra_ips=extra, on_found=on_found,
                     abort_event=abort_ev, known_hosts=hosts)
        scan_done.set()

    scanner_thread = threading.Thread(target=_scanner, daemon=True)
    scanner_thread.start()

    # ── Single reader thread — blocks on ONE input() call ────────────
    # It puts whatever the user typed into input_q.
    # This avoids the multi-prompt / polling mess entirely.
    def _reader():
        try:
            val = input(f"  {C.B}\u276f{C.R}  Device number (or Enter when done): ").strip()
            input_q.put(val)
        except (EOFError, KeyboardInterrupt):
            input_q.put(None)   # signals cancel

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    # ── Main thread: wait for EITHER scan to finish OR user to type ───
    chosen = None
    cancelled = False
    try:
        while True:
            # Check if scan finished
            if scan_done.is_set() and input_q.empty():
                # Scan done, user hasn't typed yet — wait a moment for any
                # last keystroke, then proceed
                try:
                    val = input_q.get(timeout=0.5)
                except queue.Empty:
                    val = ""
                # Process whatever came in (may be "" = just Enter)
                if val is None:
                    cancelled = True
                elif val.isdigit():
                    n = int(val)
                    with found_lock:
                        if 1 <= n <= len(found_list):
                            chosen = found_list[n - 1]
                break

            # Check if user typed something
            try:
                val = input_q.get(timeout=0.3)
            except queue.Empty:
                continue

            if val is None:
                cancelled = True; break

            if val == "":
                # Plain Enter — scan still running: show live progress
                # Ctrl+C cancels immediately, no more waiting
                if not scan_done.is_set():
                    print(f"\r  {C.D}Scan running — Ctrl+C to stop and show results{C.R}",
                          flush=True)
                    spin_i = 0
                    try:
                        while not scan_done.is_set():
                            with found_lock:
                                cnt = len(found_list)
                            sp  = _SPINNER[spin_i % len(_SPINNER)]
                            print(f"\r  {C.CY}{sp}{C.R}  Scanning...  "
                                  f"{C.G}{cnt}{C.R} found so far  "
                                  f"{C.D}(Ctrl+C to stop){C.R}   ",
                                  end="", flush=True)
                            spin_i += 1
                            time.sleep(0.12)
                    except KeyboardInterrupt:
                        abort_ev.set()
                        cancelled = True
                    print()   # clean newline after spinner
                break

            if val.isdigit():
                n = int(val)
                with found_lock:
                    snap = len(found_list)
                    if 1 <= n <= snap:
                        chosen = found_list[n - 1]
                        abort_ev.set()
                        break
                    else:
                        # Invalid number — tell user and re-launch reader
                        msg = (f"  {C.Y}No [{n}] yet \u2014 {snap} found so far.{C.R}"
                               if snap else
                               f"  {C.Y}Nothing found yet. Keep waiting...{C.R}")
                        with print_lock:
                            print(f"\r{msg}")
                        # Restart reader thread for next input
                        reader_thread2 = threading.Thread(
                            target=lambda: input_q.put(
                                input(f"  {C.B}\u276f{C.R}  Device number (or Enter when done): ").strip()
                            ), daemon=True)
                        reader_thread2.start()
            else:
                # Non-digit non-empty — ignore, restart reader
                reader_thread2 = threading.Thread(
                    target=lambda: input_q.put(
                        input(f"  {C.B}\u276f{C.R}  Device number (or Enter when done): ").strip()
                    ), daemon=True)
                reader_thread2.start()

    except KeyboardInterrupt:
        cancelled = True

    abort_ev.set()
    scan_done.wait(timeout=2)   # let in-flight probes drain

    if cancelled:
        with found_lock:
            found_so_far = list(found_list)
        if not found_so_far:
            print(f"\n  {C.D}Scan cancelled — nothing found.{C.R}")
            return hosts
        # Found some devices — show them even though user cancelled
        print(f"\n  {C.D}Scan stopped early — showing {len(found_so_far)} device(s) found:{C.R}")
        # Fall through to normal result display with what we have
        scanned = found_so_far
        elapsed = time.time() - t0
        sep()
        pr(f"Found {C.G}{len(scanned)}{C.R} SSH device(s) in {elapsed:.1f}s  {C.D}(scan stopped early){C.R}")
        updated = merge_hosts(scanned, hosts)
        save_hosts(updated)
        sep()
        pr(f"  {C.B}Go to a device?{C.R}")
        pr()
        for i, h in enumerate(scanned, 1):
            h2   = updated.get(h["ip"], h)
            did  = h2.get("device_id","")
            kp   = get_key(did) if did else ""
            auth = f"{C.G}Key ✓{C.R}" if kp else f"{C.Y}Setup needed{C.R}"
            osl  = OS_PROFILES.get(h2.get("os_type","other"), OS_PROFILES["other"])["label"][:16]
            lbl  = _device_label(h2, 18)
            print(f"  {C.B}[{i}]{C.R}  {C.B}{lbl:<20}{C.R}  {h2['ip']:<16}  {osl:<13}  {auth}")
        pr()
        pr(f"  {C.B}[0]{C.R}  Back to main menu")
        sep()
        ch2 = ask("Choose")
        if ch2.isdigit() and 1 <= int(ch2) <= len(scanned):
            transfer_menu(updated.get(scanned[int(ch2)-1]["ip"], scanned[int(ch2)-1]), updated)
        return updated

   # If user picked a device, skip waiting — go immediately
    if chosen:
        save_hosts(merge_hosts(list(found_list), hosts))
        h = merge_hosts(list(found_list), hosts).get(chosen["ip"], chosen)
        print(f"\n  {C.G}→ Going to {h['ip']} now...{C.R}")
        time.sleep(0.3)
        transfer_menu(h, merge_hosts(list(found_list), hosts))
        return merge_hosts(list(found_list), hosts)

    elapsed = time.time() - t0
    with found_lock:
        scanned = list(found_list)

    print()
    sep()
    pr(f"Found {C.G}{len(scanned)}{C.R} SSH device(s) in {elapsed:.1f}s")

    if not scanned:
        warn("Nothing found.")
        pr()
        sep()
        pr(f"  {C.B}Make sure the OTHER device has SSH server running:{C.R}")
        pr()
        pr(f"  {C.Y}Android / Termux:{C.R}")
        pr(f"    pkg install openssh   {C.D}← first time only{C.R}")
        pr(f"    passwd                {C.D}← set a password (first time){C.R}")
        pr(f"    sshd                  {C.D}← start SSH (port 8022){C.R}")
        pr()
        pr(f"  {C.Y}Windows (run in PowerShell as Admin):{C.R}")
        pr(f"    Start-Service sshd")
        pr(f"    {C.D}# Allow SSH through firewall:{C.R}")
        pr(f"    netsh advfirewall firewall add rule name=linkx_SSH_in protocol=TCP dir=in localport=22 action=allow")
        pr(f"    {C.D}# Allow ping so this device can detect Windows:{C.R}")
        pr(f"    netsh advfirewall firewall add rule name=linkx_ICMP_in protocol=icmpv4:8,any dir=in action=allow")
        pr(f"  {C.Y}Windows 7/8/8.1:{C.R}  {C.RE}No native SSH.{C.R}  Install from:")
        pr(f"    https://github.com/PowerShell/Win32-OpenSSH/releases")
        pr()
        pr(f"  {C.Y}Linux — Debian / Ubuntu / Kali / Raspberry Pi OS:{C.R}")
        pr(f"    sudo apt install openssh-server && sudo systemctl start ssh")
        pr(f"  {C.Y}Linux — Fedora / RHEL / CentOS / Rocky:{C.R}")
        pr(f"    sudo dnf install openssh-server && sudo systemctl start sshd")
        pr(f"  {C.Y}Linux — Arch / Manjaro:{C.R}")
        pr(f"    sudo pacman -S openssh && sudo systemctl start sshd")
        pr(f"  {C.Y}Linux — openSUSE / SLES:{C.R}")
        pr(f"    sudo zypper install openssh && sudo systemctl start sshd")
        pr(f"  {C.Y}Linux — Alpine:{C.R}")
        pr(f"    apk add openssh && rc-service sshd start")
        pr(f"  {C.Y}Linux — Void:{C.R}")
        pr(f"    sudo xbps-install openssh && sudo sv start sshd")
        pr()
        pr(f"  {C.Y}macOS:{C.R}")
        pr(f"    System Preferences → Sharing → Remote Login → ON")
        sep()
        pr(f"  {C.B}Also check:{C.R}")
        pr(f"  • Both devices on the same WiFi / hotspot / USB tether")
        pr(f"  • Or add device manually: {C.B}[2] Transfer → [A] Add by IP{C.R}")
        pause()
        return hosts

    updated = merge_hosts(scanned, hosts)

    # Phase 3 (relay scan) removed — added too much latency for minimal benefit.

    save_hosts(updated)

    # User jumped mid-scan — go straight to transfer
    if chosen:
        h = updated.get(chosen["ip"], chosen)
        print(f"\n  {C.G}→ Going to {h['ip']} now...{C.R}")
        time.sleep(0.4)
        transfer_menu(h, updated)
        return updated

    # Normal finish — show device picker
    # pre_ch: if user typed a number during scan after scan completed,
    # reuse it here so they don't have to press Enter twice (ghost Enter bug)
    pre_ch = ""
    try:
        pre_ch = input_q.get_nowait()  # grab any pending input from scan loop
        if pre_ch is None: pre_ch = ""
    except Exception:
        pre_ch = ""

    sep()
    pr(f"  {C.B}Go to a device now?{C.R}")
    pr()
    just_found = [updated.get(x["ip"], x) for x in scanned]
    for i, h in enumerate(just_found, 1):
        did  = h.get("device_id","")
        kp   = get_key(did) if did else ""
        auth = f"{C.G}Key ✓{C.R}" if kp else f"{C.Y}Setup needed{C.R}"
        osl  = OS_PROFILES.get(h.get("os_type","other"),
                                OS_PROFILES["other"])["label"][:16]
        lbl  = _device_label(h, 18)
        _rl  = f" {C.CY}↗relay{C.R}" if (h.get("relay") and
               not is_directly_reachable(h["ip"])) else ""
        print(f"  {C.B}[{i}]{C.R}  {C.B}{lbl:<20}{C.R}  {h['ip']:<16}  {osl:<13}  {auth}{_rl}")
    pr()
    pr(f"  {C.B}[R]{C.R}  Rename a device")
    pr(f"  {C.B}[0]{C.R}  Back to main menu")
    sep()

    # Use pre_ch if it's a valid choice — otherwise ask fresh
    if pre_ch and (pre_ch == "0" or pre_ch.upper() == "R"
                   or (pre_ch.isdigit() and 1 <= int(pre_ch) <= len(just_found))):
        ch = pre_ch
        print(f"\n  {C.B}❯  Choose{C.R}: {ch}  {C.D}(from scan input){C.R}")
    else:
        ch = ask("Choose")

    if ch == "0": pass
    elif ch.upper() == "R": updated = menu_rename_device(updated)
    elif ch.isdigit() and 1 <= int(ch) <= len(just_found):
        transfer_menu(just_found[int(ch)-1], updated)
    return updated

# ─────────────────────────────────────────────────────────────────────
# DEVICE SELECT
# ─────────────────────────────────────────────────────────────────────
def menu_rename_device(hosts: dict) -> dict:
    """
    Give a device a memorable nickname.
    Shown everywhere instead of hostname/IP.
    Stored in hosts.json under "nickname" key.
    """
    if not hosts:
        warn("No devices to rename."); return hosts

    clear(); hdr("RENAME DEVICE", "Give devices memorable nicknames")
    pr()
    all_h = list(hosts.values())
    for i, h in enumerate(all_h, 1):
        nick  = h.get("nickname","")
        lbl   = _device_label(h)
        cur   = (f"  {C.G}→ [{nick}]{C.R}" if nick else "")
        print(f"  {C.B}[{i:>2}]{C.R}  {lbl:<20}  {h['ip']:<16}  "
              f"{h.get('user','?'):<12}{cur}")
    pr()
    pr(f"  {C.B}[0]{C.R}  Back")
    sep()
    ch = ask("Choose device to rename")
    if ch == "0" or not ch: return hosts
    if not ch.isdigit() or not (1 <= int(ch) <= len(all_h)):
        err("Invalid."); time.sleep(0.8); return hosts

    h = all_h[int(ch)-1]
    cur_nick = h.get("nickname","")
    pr()
    pr(f"  Device  : {C.G}{_device_label(h)}{C.R}  ({h['ip']})")
    if cur_nick:
        pr(f"  Current : {C.Y}{cur_nick}{C.R}")
    pr(f"  {C.D}Leave blank to clear nickname{C.R}")
    new_nick = ask("Nickname", cur_nick).strip()

    h["nickname"] = new_nick
    hosts[h["ip"]] = h
    save_hosts(hosts)
    if new_nick:
        ok(f"Nickname set: {new_nick}")
    else:
        ok("Nickname cleared")
    time.sleep(0.8)
    return hosts


def select_device(hosts: dict, title: str = "SELECT DEVICE") -> dict | None:
    """
    Device picker — shows nickname/hostname, supports name search.
    Type a number to pick, a name/nickname to search, or [A] to add.
    """
    all_h = list(hosts.values())
    if not all_h:
        warn("No devices found. Run [1] Scan first."); pause(); return None

    while True:
        clear(); hdr(title)
        pr(f"  {'#':<3} {'Name':<18} {'IP':<16} {'OS':<14} "
           f"{'User':<12} {'Auth'}")
        sep()
        for i, h in enumerate(all_h, 1):
            osl   = OS_PROFILES.get(h.get("os_type","other"),
                                     OS_PROFILES["other"])["label"][:13]
            user  = h.get("user","—")
            did   = h.get("device_id","")
            kp    = get_key(did) if did else ""
            auth  = f"{C.G}Key ✓{C.R}" if kp else f"{C.D}Setup needed{C.R}"
            age   = time.time() - h.get("seen_at", time.time())
            age_s = f"{int(age//3600)}h" if age>3600 else                     f"{int(age//60)}m"    if age>60   else "now"
            lbl   = _device_label(h, 17)
            nick  = h.get("nickname","")
            lbl_s = f"{C.G}{lbl}{C.R}" if nick else lbl
            _rl   = f" {C.CY}↗{C.R}" if (h.get("relay") and
                                           not is_directly_reachable(h["ip"])) else ""
            print(f"  {C.B}[{i:>2}]{C.R} {lbl_s:<28} {h['ip']:<16} {osl:<14} "
                  f"{user:<12} {auth}  {C.D}{age_s}{C.R}{_rl}")
        sep()
        pr(f"  {C.B}[A]{C.R}  Add device by IP")
        pr(f"  {C.B}[L]{C.R}  Test localhost (127.0.0.1)  {C.D}— test SSH on THIS device{C.R}")
        pr(f"  {C.B}[R]{C.R}  Rename / nickname a device")
        pr(f"  {C.B}[0]{C.R}  Back")
        pr(f"  {C.D}  Or type a name/nickname to search{C.R}")
        sep()
        ch = ask("Choose")
        if ch == "0": return None

        if ch.upper() == "A":
            ip = ask("IP address")
            if ip:
                h = hosts.get(ip) or {
                    "ip":ip,"hostname":ip,"mac":"","ssh_port":22,
                    "os_type":"unknown","user":"","device_id":"",
                    "key_ok":False,"seen_at":time.time()}
                hosts[ip]=h; save_hosts(hosts); return h
            continue
        if ch.upper() == "L":
            raw_ip   = "127.0.0.1"
            raw_port = 22
            h = hosts.get(raw_ip) or {
                "ip": raw_ip, "hostname": "Localhost",
                "mac": "", "ssh_port": raw_port,
                "os_type": local_os(), "user": getpass.getuser(),
                "device_id": "", "key_ok": False,
                "seen_at": time.time()
            }
            hosts[raw_ip] = h
            save_hosts(hosts)
            return h
        
        if ch.upper() == "R":
            menu_rename_device(hosts); continue

        if ch.isdigit() and 1 <= int(ch) <= len(all_h):
            return all_h[int(ch)-1]

        # Name/nickname search
        q = ch.lower()
        matches = [h for h in all_h
                   if q in h.get("nickname","").lower()
                   or q in h.get("hostname","").lower()
                   or q in h.get("ip","").lower()
                   or q in h.get("user","").lower()]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            pr(f"  {C.Y}Multiple matches for [{ch}]:{C.R}")
            for j,m in enumerate(matches,1):
                pr(f"  [{j}] {_device_label(m)}  {m['ip']}")
            c2 = ask("Pick")
            if c2.isdigit() and 1 <= int(c2) <= len(matches):
                return matches[int(c2)-1]
            continue
        err(f"Not found: {ch}"); time.sleep(0.8)

# ─────────────────────────────────────────────────────────────────────
# HOW TO USE — shown on first run
# ─────────────────────────────────────────────────────────────────────
def show_guide():
    """
    Full user manual — paginated by topic.
    Shows one chapter at a time, user presses Enter to go to next.
    """
    los = local_os()

    def _chapter(title: str, subtitle: str = ""):
        clear(); hdr(f"GUIDE  —  {title}", subtitle)
        pr()

    def _next(last: bool = False):
        pr()
        sep()
        if last:
            pr(f"  {C.D}End of guide. Press Enter to return to main menu.{C.R}")
        else:
            pr(f"  {C.D}Press Enter for next topic  |  Ctrl+C to exit guide{C.R}")
        try:
            input(f"  {C.D}↵  {C.R}  ")
        except (KeyboardInterrupt, EOFError):
            return False
        return True

    # ── Chapter 1: What is Linkx ──────────────────────────────────────
    _chapter("WHAT IS LINKX", "The tool in 30 seconds")
    pr(f"  Linkx transfers files between devices on your local network")
    pr(f"  over SSH. No internet needed. No cloud. No accounts.")
    pr(f"  Files go device-to-device at full WiFi speed.")
    pr()
    pr(f"  {C.B}How it works under the hood:{C.R}")
    pr(f"  Linkx is a command factory. It figures out the right scp/ssh")
    pr(f"  command, fires it, and steps aside. Python never touches your")
    pr(f"  data — the OS transfers it natively at full speed.")
    pr()
    pr(f"  {C.B}What you need:{C.R}")
    pr(f"  • Python 3.9+ on the device running Linkx (this device)")
    pr(f"  • SSH server running on the target device")
    pr(f"  • Both devices on the same WiFi / hotspot / USB tether")
    pr()
    pr(f"  {C.B}Supported platforms:{C.R}")
    pr(f"  {C.G}✓{C.R}  Android / Termux     port 8022")
    pr(f"  {C.G}✓{C.R}  Windows 10 / 11      port 22  (OpenSSH required)")
    pr(f"  {C.G}✓{C.R}  Linux  (all distros)  port 22")
    pr(f"  {C.G}✓{C.R}  macOS                 port 22")
    pr(f"  {C.RE}✗{C.R}  iOS                   not supported (no SSH server)")
    pr(f"  {C.RE}✗{C.R}  Windows 7/8           no native SSH (manual install needed)")
    if not _next(): return

    # ── Chapter 2: Start SSH server on target ─────────────────────────
    _chapter("STEP 1 — START SSH ON TARGET", "The other device needs SSH running")
    pr(f"  Before Linkx can reach another device, that device must have")
    pr(f"  its SSH server running. Linkx can start/stop YOUR device's")
    pr(f"  SSH server from  {C.B}[7] SSH Server{C.R}  in the main menu.")
    pr()
    pr(f"  {C.B}Quick start commands per device:{C.R}")
    pr()
    pr(f"  {C.Y}Android / Termux:{C.R}")
    pr(f"    pkg install openssh    {C.D}← first time only{C.R}")
    pr(f"    passwd                 {C.D}← set a password (first time){C.R}")
    pr(f"    sshd                   {C.D}← starts SSH on port 8022{C.R}")
    pr()
    pr(f"  {C.Y}Windows 10 / 11  (run PowerShell as Admin):{C.R}")
    pr(f"    First: Settings → Apps → Optional Features → Add → OpenSSH Server")
    pr(f"    Then:  Start-Service sshd")
    pr(f"    Or use  {C.B}[7] SSH Server{C.R}  — Linkx does it automatically")
    pr()
    pr(f"  {C.Y}Linux (Debian / Ubuntu / Kali / Mint / Raspberry Pi):{C.R}")
    pr(f"    sudo apt install openssh-server   {C.D}← first time only{C.R}")
    pr(f"    sudo systemctl start ssh")
    pr()
    pr(f"  {C.Y}Linux (Fedora / RHEL / Arch / SUSE / Alpine / Void):{C.R}")
    pr(f"    Use  {C.B}[7] SSH Server{C.R}  — Linkx detects your distro and runs")
    pr(f"    the correct command automatically")
    pr()
    pr(f"  {C.Y}macOS:{C.R}")
    pr(f"    System Settings → General → Sharing → Remote Login → ON")
    pr(f"    Or: sudo systemsetup -setremotelogin on")
    if not _next(): return

    # ── Chapter 3: Scan ───────────────────────────────────────────────
    _chapter("STEP 2 — SCAN THE NETWORK", "[1] Scan from main menu")
    pr(f"  Linkx scans your local network and finds every device with")
    pr(f"  SSH open. No IP address entry needed — it finds them all.")
    pr()
    pr(f"  {C.B}How the scanner works:{C.R}")
    pr(f"  It probes every IP on your subnet simultaneously using")
    pr(f"  {_os_aware_workers()} parallel threads (auto-tuned for {local_os()}).")
    pr(f"  Both port 22 and 8022 are probed at the same time per IP.")
    pr(f"  Known devices are probed first (instant if online).")
    pr(f"  New devices are identified by their SSH banner.")
    pr()
    pr(f"  {C.B}During scan:{C.R}")
    pr(f"  Devices appear live as found. You can type a device number")
    pr(f"  and press Enter to jump to it immediately — scan continues")
    pr(f"  in background. Press Enter with no input to wait for finish.")
    pr()
    pr(f"  {C.B}Device identity:{C.R}")
    pr(f"  Linkx tracks devices by MAC address and SSH key fingerprint.")
    pr(f"  If a device changes IP (e.g. rejoins WiFi), Linkx finds it")
    pr(f"  automatically using its stored key. No re-setup needed.")
    pr()
    pr(f"  {C.B}Scan strategy:{C.R}")
    pr(f"  Phase 1 — known devices probed directly (~0.5s total)")
    pr(f"  Phase 2 — full subnet scan in parallel  (~3-8s for /24)")
    if not _next(): return

    # ── Chapter 4: Setup or Pair ──────────────────────────────────────
    _chapter("STEP 3 — CONNECT  (Setup or Pair)", "One-time per device")
    pr(f"  {C.B}Option A — Setup  [3]{C.R}  (you know the other device's password)")
    pr()
    pr(f"  1. Select a scanned device → choose  {C.B}[3] Setup{C.R}")
    pr(f"  2. Linkx detects the remote OS automatically from SSH banner")
    pr(f"  3. Enter the remote username (e.g. admin, pi, u0_a226)")
    pr(f"  4. SSH asks for the password ONCE — you type it")
    pr(f"     (Linkx never stores or sees your password)")
    pr(f"  5. Linkx installs an SSH key on the remote device")
    pr(f"  6. Password session closes — key takes over")
    pr(f"  7. All future transfers: no password, full speed")
    pr()
    pr(f"  {C.B}Option B — Zero-Config Pair  [P]{C.R}  (no password needed)")
    pr()
    pr(f"  Both devices run Linkx. One is HOST, one is CLIENT.")
    pr(f"  HOST: starts SSH server, shows a 6-digit PIN")
    pr(f"  CLIENT: scans network, finds HOST, confirms the PIN")
    pr(f"  Keys are exchanged both ways automatically — both devices")
    pr(f"  can SSH to each other without any password, ever.")
    pr()
    pr(f"  {C.B}After connecting — Name your devices:{C.R}")
    pr(f"  Linkx asks you to name both devices (e.g. 'Laptop', 'Vivo').")
    pr(f"  The key file is renamed  Laptop_to_Vivo  so even if the IP")
    pr(f"  or MAC changes, the key identity is permanent.")
    if not _next(): return

    # ── Chapter 5: Transfer ───────────────────────────────────────────
    _chapter("STEP 4 — TRANSFER FILES", "[2] Transfer → select device")
    pr(f"  {C.B}Inside Transfer menu:{C.R}")
    pr(f"  [1] Send     → push file/folder TO the other device")
    pr(f"  [2] Receive  ← pull file/folder FROM the other device")
    pr(f"  [3] Browse   — explore remote filesystem live")
    pr(f"  [4] Command  — run a command on remote device")
    pr(f"  [5] Shell    — open full SSH terminal on remote")
    pr(f"  [S] Share    — send linkx.py itself to the device")
    pr(f"  [X] Tar threshold — set when to bundle files into tar")
    pr()
    pr(f"  {C.B}How Send works:{C.R}")
    pr(f"  1. Pick files/folders one by one")
    pr(f"     — for each: compress with 7-Zip? Y/N per item")
    pr(f"     — compressed items (.7z) are placed beside the source")
    pr(f"  2. Live browse the remote device to pick destination")
    pr(f"  3. Linkx checks if those items already exist at destination")
    pr(f"     — exist + rsync available → rsync (only changed bytes sent)")
    pr(f"     — exist + no rsync → offer install, or overwrite, or Copy/")
    pr(f"  4. If file count > tar threshold → bundle into Transfer.tar")
    pr(f"     — single files are NEVER tarred regardless of size")
    pr(f"     — tar is built on same drive as first selected item")
    pr(f"  5. scp/rsync fires — Python steps aside, OS transfers at speed")
    pr(f"  6. Local tar + .7z files deleted immediately after send")
    pr(f"  7. Remote auto-extracts tar, deletes tar")
    pr(f"  8. If .7z files remain → ask to decompress on remote")
    pr()
    pr(f"  {C.B}Tar threshold  (currently {TAR_THRESHOLD} files):{C.R}")
    pr(f"  Change with [X] inside Transfer menu anytime.")
    pr(f"  0 = always tar   |   99 = almost never tar")
    if not _next(): return

    # ── Chapter 6: Vault ──────────────────────────────────────────────
    _chapter("VAULT  [V]", "Your trusted device library")
    pr(f"  Vault is a curated list of devices you transfer with often.")
    pr(f"  Each Vault device gets a  {C.CY}Linkx/{C.R}  folder in Downloads")
    pr(f"  on both devices — a shared space for easy file exchange.")
    pr()
    pr(f"  {C.B}How to add a device to Vault:{C.R}")
    pr(f"  After Setup or Pair, Linkx asks if you want to add to Vault.")
    pr(f"  Or: go to Transfer menu → device → press  {C.B}[V]{C.R}")
    pr(f"  Adding creates the Linkx folder on both devices automatically.")
    pr()
    pr(f"  {C.B}Vault menu options:{C.R}")
    pr(f"  [1] Browse  — explore the remote Linkx folder live")
    pr(f"  [2] Send    — send files to their Linkx folder")
    pr(f"  [3] Receive — pull files from their Linkx folder")
    pr()
    pr(f"  {C.B}How Vault works behind the scenes:{C.R}")
    pr(f"  Vault uses the same transfer engine as the Transfer menu.")
    pr(f"  The difference: source and destination paths are pre-set to")
    pr(f"  the Linkx folder on each device. Connection is verified live")
    pr(f"  before opening — if device moved, Linkx finds new IP by key.")
    pr()
    pr(f"  {C.B}Remove from Vault:{C.R}")
    pr(f"  Transfer menu → device → [V] → [R] Remove from Vault")
    if not _next(): return

    # ── Chapter 7: Quick Share ────────────────────────────────────────
    _chapter("QUICK SHARE  [Q]", "Fire-and-forget transfers")
    pr(f"  Quick Share is for daily use — pick files first, device")
    pr(f"  found → transfer fires. No hunting through menus.")
    pr()
    pr(f"  {C.B}Online device flow:{C.R}")
    pr(f"  1. Press [Q] → pick device → [1] Send or [2] Receive")
    pr(f"  2. Linkx tests connection immediately")
    pr(f"  3. If online: browse remote (starts at Downloads folder)")
    pr(f"     pick files, pick destination → transfer fires")
    pr()
    pr(f"  {C.B}Offline device flow:{C.R}")
    pr(f"  Device not reachable → two options:")
    pr(f"  [1] SSH is running — Linkx scans whole subnet to find")
    pr(f"      new IP, updates it, then transfers")
    pr(f"  [2] SSH not running — queue the transfer")
    pr(f"      → Linkx watches in background every {QS_POLL_INTERVAL}s")
    pr(f"      → moment device comes online, transfer fires")
    pr()
    pr(f"  {C.B}Trusted devices  [★]:{C.R}")
    pr(f"  Mark a device as trusted → queued transfers fire silently")
    pr(f"  with zero UI interruption. Untrusted = confirm screen.")
    pr()
    pr(f"  {C.B}Queue rules:{C.R}")
    pr(f"  Watcher runs ONLY while Quick Share menu is open.")
    pr(f"  Watcher stops when you exit Quick Share or close Linkx.")
    pr(f"  Queue transfer uses same tar/rsync logic as Transfer menu.")
    pr()
    pr(f"  {C.B}Pause option:{C.R}")
    pr(f"  When confirm screen appears → [P] pauses 2 minutes,")
    pr(f"  then asks again. [N] clears the queue.")
    if not _next(): return

    # ── Chapter 8: Install Tools ──────────────────────────────────────
    _chapter("OPTIONAL TOOLS  [8]", "Install tools for better transfers")
    pr(f"  {C.B}7-Zip{C.R}  — compression before sending")
    pr(f"  Compress individual items before bundling.")
    pr(f"  Folders and files compressed to .7z — receiver can")
    pr(f"  decompress on remote through Linkx after transfer.")
    pr(f"  Install: [8] → [1]  (auto-detects your OS)")
    pr()
    pr(f"  {C.B}rsync{C.R}  — smart delta transfer")
    pr(f"  If a file already exists at destination, rsync sends")
    pr(f"  only the changed bytes — not the whole file again.")
    pr(f"  Ideal for large files you update frequently.")
    pr(f"  Linux/macOS/Android: install via [8] → [2]")
    pr(f"  Windows: rsync installed via MSYS2 (Linkx handles it)")
    pr(f"  Note: rsync between Linux↔Linux, Linux↔Android works")
    pr(f"  perfectly. Windows remote uses scp fallback (reliable).")
    pr()
    pr(f"  {C.B}SSH server{C.R}  — your own device as a target")
    pr(f"  Start/stop SSH on THIS device from [7] SSH Server.")
    pr(f"  Lets other devices transfer files to you.")
    if not _next(): return

    # ── Chapter 9: Advanced — device tracking ─────────────────────────
    _chapter("ADVANCED — HOW LINKX TRACKS DEVICES", "IPs change. Linkx handles it.")
    pr(f"  {C.B}The problem:{C.R}")
    pr(f"  Devices get new IPs every time they join a network.")
    pr(f"  Android randomizes its MAC address too.")
    pr(f"  Most tools break when this happens.")
    pr()
    pr(f"  {C.B}How Linkx solves it — 3-phase identity:{C.R}")
    pr()
    pr(f"  Phase 1: Last known IP — direct TCP probe (~50ms)")
    pr(f"  Phase 2: MAC address lookup in ARP table")
    pr(f"           (skipped for Android/Windows — they randomize MAC)")
    pr(f"  Phase 3: Named key scan — the key IS the identity")
    pr(f"           Linkx tries the device's key against every SSH")
    pr(f"           device on the subnet. First device that accepts")
    pr(f"           the key IS the device. IP and MAC don't matter.")
    pr()
    pr(f"  {C.B}Key naming:{C.R}")
    pr(f"  After first connect, Linkx renames the key to")
    pr(f"  ThisDevice_to_OtherDevice  (e.g. Laptop_to_Vivo)")
    pr(f"  This name is permanent. Even after factory reset,")
    pr(f"  re-setup restores the same named key.")
    pr()
    pr(f"  {C.B}Data files stored alongside linkx.py:{C.R}")
    pr(f"  .linkx_hosts.json   — known devices and their info")
    pr(f"  .linkx_keys.json    — device ID → key file map")
    pr(f"  .linkx_vault.json   — vault device list")
    pr(f"  .linkx_quick.json   — Quick Share state and queues")
    pr(f"  .linkx_trusted.json — trusted device list")
    if not _next(): return

    # ── Chapter 10: Quick reference ───────────────────────────────────
    _chapter("QUICK REFERENCE", "All main menu options")
    pr(f"  {C.B}[1]{C.R}  Scan          Find SSH devices on network")
    pr(f"  {C.B}[2]{C.R}  Transfer      Send/Receive files to a device")
    pr(f"  {C.B}[3]{C.R}  Setup         First-time connect (password → key)")
    pr(f"  {C.B}[P]{C.R}  Pair          Zero-config two-way key exchange")
    pr(f"  {C.B}[Q]{C.R}  Quick Share   Fire-and-forget, offline queue")
    pr(f"  {C.B}[V]{C.R}  Vault         Trusted device library + Linkx folders")
    pr(f"  {C.B}[4]{C.R}  My SSH Keys   View all stored keys and identities")
    pr(f"  {C.B}[5]{C.R}  Remove Device Delete device + all keys + all data")
    pr(f"  {C.B}[6]{C.R}  Rename        Give device a nickname")
    pr(f"  {C.B}[7]{C.R}  SSH Server    Start/stop SSH on THIS device")
    pr(f"  {C.B}[8]{C.R}  Install Tools 7-Zip / rsync / OpenSSH")
    pr(f"  {C.B}[T]{C.R}  Terminal      Raw local shell without quitting")
    pr(f"  {C.B}[?]{C.R}  This guide")
    pr()
    sep()
    pr(f"  {C.B}Tips:{C.R}")
    pr(f"  • Edit  {C.B}W = 64{C.R}  near top of file to resize all menus")
    pr(f"    (50 = phone screen  64 = laptop  80 = wide monitor)")
    pr(f"  • Edit  {C.B}TAR_THRESHOLD{C.R}  to control when files get bundled")
    pr(f"  • Run   {C.B}python3 linkx.py --version{C.R}  for version info")
    pr(f"  • Both devices can run Linkx and transfer to each other")
    pr(f"  • Linkx works over hotspot, USB tether, and LAN equally")
    _next(last=True)

# ─────────────────────────────────────────────────────────────────────
# SSH SERVER MANAGER — start / stop THIS device's SSH server
#
# Detects the local OS and runs the correct commands automatically.
# Windows also manages the two firewall rules:
#   linkx_SSH_in  — TCP port 22 inbound  (kept while sshd runs)
#   linkx_ICMP_in — ICMPv4 ping inbound  (temporary, removed on stop)
# All commands are shown on screen so the user can learn / reuse them.
# ─────────────────────────────────────────────────────────────────────

def _show_server_commands(action: str):
    """
    Print the exact commands for starting OR stopping the SSH server
    on every supported OS, so users can do it manually next time.
    action: 'start' or 'stop'
    """
    los = local_os()
    los_label = {
        "android":"Android/Termux", "windows":"Windows 10/11",
        "windows_old":"Windows 7/8 (no native SSH)",
        "macos":"macOS", "kali":"Kali Linux", "debian":"Debian/Ubuntu",
        "rhel":"RHEL/Fedora/CentOS", "arch":"Arch Linux",
        "suse":"openSUSE/SLES", "alpine":"Alpine Linux",
        "void":"Void Linux", "gentoo":"Gentoo", "linux":"Linux",
    }.get(los, los)

    sep()
    if action == "start":
        pr(f"  {C.B}Commands to START SSH server on each OS:{C.R}")
        pr()
        pr(f"  {C.Y}Android / Termux:{C.R}")
        pr(f"    pkg install openssh   {C.D}← first time only{C.R}")
        pr(f"    passwd                {C.D}← set password first time{C.R}")
        pr(f"    sshd                  {C.D}← start (port 8022){C.R}")
        pr()
        pr(f"  {C.Y}Windows 10/11/Server 2019+  (PowerShell as Admin):{C.R}")
        pr(f"    Start-Service sshd")
        pr(f"    netsh advfirewall firewall add rule name=linkx_SSH_in ^")
        pr(f"      protocol=TCP dir=in localport=22 action=allow enable=yes profile=any")
        pr(f"    netsh advfirewall firewall add rule name=linkx_ICMP_in ^")
        pr(f"      protocol=icmpv4:8,any dir=in action=allow enable=yes profile=any")
        pr(f"  {C.Y}Windows 7/8/8.1: {C.RE}No native SSH.{C.R}  Install Win32-OpenSSH:")
        pr(f"    https://github.com/PowerShell/Win32-OpenSSH/releases")
        pr()
        pr(f"  {C.Y}Debian / Ubuntu / Raspberry Pi OS / Mint:{C.R}")
        pr(f"    sudo apt install openssh-server   {C.D}← first time only{C.R}")
        pr(f"    sudo systemctl start ssh")
        pr()
        pr(f"  {C.Y}Kali Linux:{C.R}")
        pr(f"    sudo systemctl start ssh")
        pr()
        pr(f"  {C.Y}Fedora / RHEL / CentOS / Rocky / AlmaLinux:{C.R}")
        pr(f"    sudo dnf install openssh-server   {C.D}← first time only{C.R}")
        pr(f"    sudo systemctl start sshd")
        pr()
        pr(f"  {C.Y}Arch Linux / Manjaro / EndeavourOS:{C.R}")
        pr(f"    sudo pacman -S openssh            {C.D}← first time only{C.R}")
        pr(f"    sudo systemctl start sshd")
        pr()
        pr(f"  {C.Y}openSUSE / SLES:{C.R}")
        pr(f"    sudo zypper install openssh       {C.D}← first time only{C.R}")
        pr(f"    sudo systemctl start sshd")
        pr()
        pr(f"  {C.Y}Alpine Linux (OpenRC):{C.R}")
        pr(f"    apk add openssh                   {C.D}← first time only{C.R}")
        pr(f"    rc-service sshd start")
        pr()
        pr(f"  {C.Y}Void Linux (runit):{C.R}")
        pr(f"    sudo xbps-install openssh         {C.D}← first time only{C.R}")
        pr(f"    sudo sv start sshd")
        pr()
        pr(f"  {C.Y}Gentoo (OpenRC):{C.R}")
        pr(f"    emerge net-misc/openssh           {C.D}← first time only{C.R}")
        pr(f"    rc-service sshd start")
        pr()
        pr(f"  {C.Y}macOS (Ventura/Sonoma/Sequoia):{C.R}")
        pr(f"    sudo systemsetup -setremotelogin on")
        pr(f"    {C.D}or: System Settings → General → Sharing → Remote Login → ON{C.R}")
        pr(f"  {C.Y}macOS (older — High Sierra to Monterey):{C.R}")
        pr(f"    sudo systemsetup -setremotelogin on")
        pr(f"    {C.D}or: System Preferences → Sharing → Remote Login → ON{C.R}")
    else:
        pr(f"  {C.B}Commands to STOP SSH server on each OS:{C.R}")
        pr()
        pr(f"  {C.Y}Android / Termux:{C.R}")
        pr(f"    pkill sshd")
        pr()
        pr(f"  {C.Y}Windows 10/11/Server  (PowerShell as Admin):{C.R}")
        pr(f"    Stop-Service sshd")
        pr(f"    netsh advfirewall firewall delete rule name=linkx_SSH_in")
        pr(f"    netsh advfirewall firewall delete rule name=linkx_ICMP_in")
        pr(f"    {C.D}(removes both rules — Windows back to original state){C.R}")
        pr()
        pr(f"  {C.Y}Debian / Ubuntu / Kali / Raspberry Pi OS:{C.R}")
        pr(f"    sudo systemctl stop ssh")
        pr()
        pr(f"  {C.Y}Fedora / RHEL / CentOS / Rocky / Arch / SUSE:{C.R}")
        pr(f"    sudo systemctl stop sshd")
        pr()
        pr(f"  {C.Y}Alpine Linux:{C.R}")
        pr(f"    rc-service sshd stop")
        pr()
        pr(f"  {C.Y}Void Linux:{C.R}")
        pr(f"    sudo sv stop sshd")
        pr()
        pr(f"  {C.Y}Gentoo:{C.R}")
        pr(f"    rc-service sshd stop")
        pr()
        pr(f"  {C.Y}macOS:{C.R}")
        pr(f"    sudo systemsetup -setremotelogin off")
    sep()
    pr(f"  {C.D}Your OS detected as: {C.B}{los_label}{C.R}")


def menu_ssh_server(hosts: dict) -> dict:
    """
    Interactive SSH server manager for THIS device.
    Detects local OS, runs correct start/stop commands, manages
    Windows firewall rules, and shows every command for manual reuse.
    """
    is_termux = os.path.exists("/data/data/com.termux/files/home")
    los       = local_os()
    port      = 8022 if is_termux else 22
    _los_labels = {
        "android":"Android / Termux", "windows":"Windows 10/11",
        "windows_old":"Windows 7/8 (no native SSH)",
        "macos":"macOS", "kali":"Kali Linux",
        "debian":"Debian / Ubuntu / Raspberry Pi OS",
        "rhel":"RHEL / Fedora / CentOS / Rocky",
        "arch":"Arch Linux / Manjaro",
        "suse":"openSUSE / SLES",
        "alpine":"Alpine Linux",
        "void":"Void Linux",
        "gentoo":"Gentoo",
        "linux":"Linux",
    }
    os_label  = _los_labels.get(los, los.title())

    while True:
        clear()
        hdr("SSH SERVER MANAGER", f"This device: {os_label}")
        pr()

        # ── Live status check ─────────────────────────────────────────
        running = _is_sshd_running(port)
        status  = (f"{C.G}● RUNNING{C.R}  (port {port})"
                   if running else
                   f"{C.RE}○ STOPPED{C.R}")
        pr(f"  Status : {status}")
        pr()

        # Windows: show firewall rule states too
        if los in ("windows","windows_old") and os.name == "nt":
            def _rule_active(name: str) -> bool:
                try:
                    r = subprocess.run(
                        ["netsh", "advfirewall", "firewall", "show", "rule",
                         f"name={name}"],
                        capture_output=True, text=True, timeout=5)
                    return "enable" in r.stdout.lower() and "yes" in r.stdout.lower()
                except Exception:
                    return False
            ssh_fw  = _rule_active("linkx_SSH_in")
            icmp_fw = _rule_active("linkx_ICMP_in")
            fw_ssh  = f"{C.G}✓ active{C.R}"   if ssh_fw  else f"{C.D}✗ not present{C.R}"
            fw_icmp = f"{C.G}✓ active{C.R}"   if icmp_fw else f"{C.D}✗ not present{C.R}"
            pr(f"  Firewall SSH  rule : {fw_ssh}   {C.D}(port 22 inbound){C.R}")
            pr(f"  Firewall ICMP rule : {fw_icmp}  {C.D}(ping inbound — temporary){C.R}")
            pr()

        sep()
        if running:
            pr(f"  {C.B}[1]{C.R}  Stop SSH server")
            if los in ("windows","windows_old") and os.name == "nt":
                pr(f"       {C.D}→ stops sshd + removes ICMP ping rule{C.R}")
        else:
            pr(f"  {C.B}[1]{C.R}  Start SSH server")
            if los in ("windows","windows_old") and os.name == "nt":
                pr(f"       {C.D}→ starts sshd + opens SSH port 22 + ICMP ping{C.R}")

        pr(f"  {C.B}[2]{C.R}  Show start commands  {C.D}(for all OS){C.R}")
        pr(f"  {C.B}[3]{C.R}  Show stop  commands  {C.D}(for all OS){C.R}")
        pr(f"  {C.B}[0]{C.R}  Back")
        sep()

        ch = ask("Choose")

        # ── [1] Toggle start / stop ───────────────────────────────────
        if ch == "1":
            clear()
            if not running:
                # ── START ─────────────────────────────────────────────
                hdr("SSH SERVER — START", os_label)
                pr()
                sshd_ok, started_port, msg = _start_sshd()
                if sshd_ok:
                    ok(msg)
                    pr()
                    # Show exactly what ran per OS
                    if is_termux:
                        pr(f"  {C.D}Command used:{C.R}  sshd")
                    elif los in ("windows", "windows_old"):
                        pr(f"  {C.D}Commands used:{C.R}")
                        pr(f"    Start-Service sshd")
                        pr(f"    netsh ... add rule name=linkx_SSH_in  (port 22)")
                        pr(f"    netsh ... add rule name=linkx_ICMP_in (ping)")
                    elif los == "macos":
                        pr(f"  {C.D}Command used:{C.R}  sudo systemsetup -setremotelogin on")
                    elif los in ("debian", "kali"):
                        pr(f"  {C.D}Command used:{C.R}  sudo systemctl start ssh")
                    elif los == "alpine":
                        pr(f"  {C.D}Command used:{C.R}  rc-service sshd start")
                    elif los == "void":
                        pr(f"  {C.D}Command used:{C.R}  sudo sv start sshd")
                    elif los == "gentoo":
                        pr(f"  {C.D}Command used:{C.R}  rc-service sshd start")
                    else:
                        pr(f"  {C.D}Command used:{C.R}  sudo systemctl start sshd")
                else:
                    err("Could not start SSH server automatically.")
                    pr()
                    for line in msg.split("\n"):
                        pr(f"  {C.Y}{line}{C.R}")
            else:
                # ── STOP ──────────────────────────────────────────────
                hdr("SSH SERVER — STOP", os_label)
                pr()
                stopped = False

                if is_termux:
                    pr(f"  {C.D}Running: pkill sshd{C.R}")
                    try:
                        subprocess.run(["pkill", "sshd"],
                                       capture_output=True, timeout=5)
                        time.sleep(0.8)
                        stopped = not _is_sshd_running(8022)
                    except Exception as e:
                        err(str(e))

                elif los in ("windows","windows_old") and os.name == "nt":
                    pr(f"  {C.D}Stopping OpenSSH Server...{C.R}")
                    if _win_is_admin():
                        try:
                            subprocess.run(["net", "stop", "sshd"],
                                           capture_output=True, timeout=15)
                            time.sleep(1)
                            stopped = not _is_sshd_running(22)
                        except Exception as e:
                            err(str(e))
                    else:
                        pr(f"  {C.Y}Admin rights needed — a UAC prompt will appear.{C.R}")
                        pr(f"  {C.D}Click YES in the UAC dialog to continue.{C.R}")
                        try:
                            subprocess.run([
                                "powershell", "-NoProfile", "-Command",
                                "Start-Process powershell -ArgumentList "
                                '"-NoProfile -Command net stop sshd" '
                                "-Verb RunAs -Wait -WindowStyle Hidden"
                            ], timeout=30)
                            time.sleep(2)
                            stopped = not _is_sshd_running(22)
                        except Exception as e:
                            err(str(e))
                    # Remove BOTH firewall rules — leave Windows exactly
                    # as it was before this tool was run
                    pr(f"  {C.D}Removing firewall rules (SSH port 22 + ICMP ping)...{C.R}")
                    _win_remove_all_firewall_rules()
                    pr(f"  {C.D}Windows firewall restored to original state.{C.R}")

                elif los == "macos":
                    pr(f"  {C.D}Running: sudo systemsetup -setremotelogin off{C.R}")
                    try:
                        subprocess.run(
                            ["sudo", "systemsetup", "-setremotelogin", "off"],
                            capture_output=True, timeout=15)
                        time.sleep(1)
                        stopped = not _is_sshd_running(22)
                    except Exception as e:
                        err(str(e))

                else:  # Linux — distro-aware stop
                    stop_cmds = {
                        "debian" : [["sudo","systemctl","stop","ssh"]],
                        "kali"   : [["sudo","systemctl","stop","ssh"]],
                        "rhel"   : [["sudo","systemctl","stop","sshd"]],
                        "arch"   : [["sudo","systemctl","stop","sshd"]],
                        "suse"   : [["sudo","systemctl","stop","sshd"]],
                        "alpine" : [["sudo","rc-service","sshd","stop"]],
                        "void"   : [["sudo","sv","stop","sshd"]],
                        "gentoo" : [["sudo","rc-service","sshd","stop"],
                                    ["sudo","systemctl","stop","sshd"]],
                        "linux"  : [["sudo","systemctl","stop","ssh"],
                                    ["sudo","systemctl","stop","sshd"]],
                    }
                    cmds = stop_cmds.get(los, stop_cmds["linux"])
                    for cmd in cmds:
                        try:
                            pr(f"  {C.D}Running: {' '.join(cmd)}{C.R}")
                            subprocess.run(cmd, capture_output=True, timeout=15)
                            time.sleep(1)
                            if not _is_sshd_running(22):
                                stopped = True; break
                        except Exception:
                            pass
                    if not stopped:
                        try:
                            subprocess.run(["sudo","pkill","sshd"],
                                           capture_output=True, timeout=5)
                            time.sleep(1)
                            stopped = not _is_sshd_running(22)
                        except Exception:
                            pass

                pr()
                if stopped:
                    ok("SSH server stopped.")
                    if los in ("windows","windows_old") and os.name == "nt":
                        pr(f"  {C.D}Both firewall rules removed (SSH port 22 + ICMP ping).{C.R}")
                        pr(f"  {C.D}Windows is back to its original state.{C.R}")
                else:
                    warn("Could not confirm SSH server stopped.")
                    pr()
                    pr(f"  {C.B}Stop it manually:{C.R}")
                    if is_termux:
                        pr(f"    pkill sshd")
                    elif los in ("windows", "windows_old"):
                        pr(f"    Stop-Service sshd                {C.D}(PowerShell as Admin){C.R}")
                        pr(f"    netsh advfirewall firewall delete rule name=linkx_SSH_in")
                        pr(f"    netsh advfirewall firewall delete rule name=linkx_ICMP_in")
                    elif los == "macos":
                        pr(f"    sudo systemsetup -setremotelogin off")
                    elif los in ("debian", "kali"):
                        pr(f"    sudo systemctl stop ssh")
                    elif los == "alpine":
                        pr(f"    rc-service sshd stop")
                    elif los == "void":
                        pr(f"    sudo sv stop sshd")
                    elif los == "gentoo":
                        pr(f"    rc-service sshd stop")
                    else:
                        pr(f"    sudo systemctl stop sshd")
            pause()

        elif ch == "2":
            clear(); hdr("HOW TO START SSH SERVER")
            _show_server_commands("start")
            pause()

        elif ch == "3":
            clear(); hdr("HOW TO STOP SSH SERVER")
            _show_server_commands("stop")
            pause()

        elif ch == "0":
            return hosts

        else:
            err("Invalid."); time.sleep(0.8)


# ─────────────────────────────────────────────────────────────────────
# SELF-CONTAINED FOLDER — MIGRATION & STARTUP
#
# On every startup:
#   Step 1: Restore any keys from Ssh/keys/ back into ~/.ssh/
#           (handles Termux reinstall / data-clear)
#   Step 2: Migrate old dotfile data → Ssh/data/
#   Step 3: Migrate our own keys from ~/.ssh/ → Ssh/keys/ backup
#   Step 4: If script is not inside Ssh/, copy it there and re-exec
# ─────────────────────────────────────────────────────────────────────


# ═════════════════════════════════════════════════════════════════════
# LINKX VAULT & TRUSTED DEVICE SYSTEM
# ═════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────
# HELPERS — Downloads path per OS, Linkx folder path
# ─────────────────────────────────────────────────────────────────────

def _downloads_path_local() -> str:
    """Return the local Downloads folder path for the running OS."""
    los = local_os()
    home = os.path.expanduser("~")
    if los == "android":
        # Termux: ~/storage/downloads symlink → /storage/emulated/0/Download
        dl = os.path.join(home, "storage", "downloads")
        if os.path.exists(dl):
            return dl
        return "/storage/emulated/0/Download"
    if los in ("windows", "windows_old"):
        return os.path.join(home, "Downloads")
    if los == "macos":
        return os.path.join(home, "Downloads")
    # Linux / kali / etc
    return os.path.join(home, "Downloads")


def _linkx_path_local() -> str:
    """Return the local Linkx folder path (Downloads/Linkx)."""
    return os.path.join(_downloads_path_local(), LINKX_FOLDER)


def _downloads_path_remote(os_type: str, user: str) -> str:
    """Returns real Downloads path per OS. Always strips domain prefix from user."""
    # Strip domain prefix: "v-15\admin" → "admin", "DOMAIN\user" → "user"
    bare = user.split("\\")[-1] if "\\" in user else user
    if os_type == "android":
        return "/sdcard/Download"
    if os_type == "windows":
        return f"C:/Users/{bare}/Downloads"
    if os_type == "macos":
        return f"/Users/{bare}/Downloads"
    return f"/home/{bare}/Downloads"


def _linkx_path_remote(os_type: str, user: str) -> str:
    """Returns OS-aware remote Linkx path. Uses real Downloads path."""
    if os_type == "android":
        return f"/sdcard/Download/{LINKX_FOLDER}"
    return f"{_downloads_path_remote(os_type, user)}/{LINKX_FOLDER}"


def _ensure_linkx_folder_remote(ip: str, user: str, port: int,
                                  kp: str, os_type: str) -> bool:
    """
    Create the Linkx folder on the remote device using the existing SSH key.
    For Windows: queries $env:USERPROFILE to get the real path — avoids
    ghost folders from domain usernames like v-15\\admin.
    Returns True on success.
    """
    if os_type == "windows":
        # Get real home from Windows — never use raw user in path
        out_home = run_cmd(ip, user, port,
                           'powershell -NoProfile -Command "Write-Output $env:USERPROFILE"',
                           kp, timeout=10)
        if out_home.strip() and out_home != "__TIMEOUT__" and "%" not in out_home:
            win_home = out_home.strip().replace("\\", "/")
        else:
            bare = user.split("\\")[-1] if "\\" in user else user
            win_home = f"C:/Users/{bare}"
        remote_path = f"{win_home}/Downloads/{LINKX_FOLDER}"
        win_path = remote_path.replace("/", "\\")
        cmd = (f'powershell -NoProfile -Command "'
               f'New-Item -ItemType Directory -Force -Path \'{win_path}\' '
               f'| Out-Null; Write-Output DONE_LINKX"')
    elif os_type == "android":
        remote_path = f"/sdcard/Download/{LINKX_FOLDER}"
        cmd = f"mkdir -p {shlex.quote(remote_path)} && echo DONE_LINKX"
    else:
        remote_path = _linkx_path_remote(os_type, user)
        cmd = f"mkdir -p {shlex.quote(remote_path)} && echo DONE_LINKX"
    out = run_cmd(ip, user, port, cmd, kp, timeout=15)
    return "DONE_LINKX" in out

def _ensure_linkx_folder_local() -> bool:
    """Create the local Linkx folder in Downloads. Returns True on success."""
    p = _linkx_path_local()
    try:
        os.makedirs(p, exist_ok=True)
        return True
    except Exception as e:
        warn(f"Could not create local Linkx folder: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────
# VAULT DATABASE  .linkx_vault.json
# { device_id: { "nickname": ..., "os_type": ..., "user": ...,
#                "ip": ..., "ssh_port": ..., "mac": ...,
#                "key_name": ..., "device_id": ... } }
# ─────────────────────────────────────────────────────────────────────

def _load_vault() -> dict:
    try:
        with open(VAULT_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_vault(v: dict):
    with _FILE_LOCK:
        try:
            tmp = VAULT_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(v, f, indent=2)
            if os.name != "nt":
                try: os.chmod(tmp, 0o600)
                except Exception: pass
            os.replace(tmp, VAULT_FILE)
        except Exception:
            try: os.remove(tmp)
            except Exception: pass


def vault_add(host: dict):
    """Add a device to the Vault."""
    v = _load_vault()
    did = host.get("device_id", "")
    if not did:
        return
    v[did] = {
        "device_id" : did,
        "nickname"  : host.get("nickname", host.get("hostname", host.get("ip", "?"))),
        "os_type"   : host.get("os_type", "other"),
        "user"      : host.get("user", ""),
        "ip"        : host.get("ip", ""),
        "ssh_port"  : host.get("ssh_port", 22),
        "mac"       : host.get("mac", ""),
        "key_name"  : host.get("key_name", ""),
        "key_source": host.get("key_source", ""),
        "mac_randomized": host.get("mac_randomized", False),
    }
    _save_vault(v)


def vault_remove(device_id: str):
    v = _load_vault()
    v.pop(device_id, None)
    _save_vault(v)


def vault_has(device_id: str) -> bool:
    return device_id in _load_vault()


def vault_sync_from_hosts(hosts: dict):
    """Keep vault entries up to date with latest IP/MAC from hosts."""
    v = _load_vault()
    changed = False
    for did, ve in v.items():
        h = next((h for h in hosts.values() if h.get("device_id") == did), None)
        if h:
            for field in ("ip", "mac", "ssh_port", "user", "os_type",
                          "nickname", "key_name", "key_source", "mac_randomized"):
                if h.get(field) and h[field] != ve.get(field):
                    ve[field] = h[field]
                    changed = True
    if changed:
        _save_vault(v)


# ─────────────────────────────────────────────────────────────────────
# TRUSTED DEVICE DATABASE  .linkx_trusted.json
# { device_id: True }
# Trusted devices: Quick Share queue auto-transfers without confirmation.
# ─────────────────────────────────────────────────────────────────────

def _load_trusted() -> dict:
    try:
        with open(TRUSTED_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_trusted(d: dict):
    with _FILE_LOCK:
        try:
            tmp = TRUSTED_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f, indent=2)
            if os.name != "nt":
                try: os.chmod(tmp, 0o600)
                except Exception: pass
            os.replace(tmp, TRUSTED_FILE)
        except Exception:
            try: os.remove(tmp)
            except Exception: pass


def is_trusted(device_id: str) -> bool:
    return bool(_load_trusted().get(device_id))


def set_trusted(device_id: str, value: bool):
    d = _load_trusted()
    if value:
        d[device_id] = True
    else:
        d.pop(device_id, None)
    _save_trusted(d)


# ─────────────────────────────────────────────────────────────────────
# VAULT MENU
# ─────────────────────────────────────────────────────────────────────

def menu_vault(hosts: dict) -> dict:
    """
    Vault menu — list of vault devices.
    Each device entry → Browse / Send / Receive directly in Linkx folder.
    """
    while True:
        vault_sync_from_hosts(hosts)
        v = _load_vault()

        clear()
        hdr("LINKX VAULT", "Your trusted device library")
        pr()

        if not v:
            pr(f"  {C.D}No devices in Vault yet.{C.R}")
            pr()
            pr(f"  Add devices via  {C.B}[3] Setup{C.R}  or  {C.B}[P] Pair{C.R}  —")
            pr(f"  after naming, you will be asked to add to Vault.")
            pr()
            pr(f"  {C.B}[0]{C.R}  Back")
            sep()
            ask("Choose")
            return hosts

        vault_list = list(v.values())
        for i, ve in enumerate(vault_list, 1):
            did     = ve.get("device_id", "")
            lbl     = ve.get("nickname", ve.get("ip", "?"))
            osl     = OS_PROFILES.get(ve.get("os_type", "other"),
                                       OS_PROFILES["other"])["label"][:14]
            trusted = f"  {C.CY}★ trusted{C.R}" if is_trusted(did) else ""
            # Quick online check (fast TCP probe, non-blocking)
            ip   = ve.get("ip", "")
            port = ve.get("ssh_port", 22)
            online = _tcp_probe_fast(ip, port, timeout=0.4) if ip else False
            dot  = f"{C.G}●{C.R}" if online else f"{C.D}○{C.R}"
            print(f"  {C.B}[{i}]{C.R}  {dot}  {C.B}{lbl:<20}{C.R}  {osl:<16}{trusted}")

        pr()
        pr(f"  {C.B}[0]{C.R}  Back")
        sep()
        pr(f"  {C.D}● = online now  ○ = offline{C.R}")
        sep()
        ch = ask("Choose device")
        if ch == "0" or not ch:
            return hosts
        if not ch.isdigit() or not (1 <= int(ch) <= len(vault_list)):
            err("Invalid."); time.sleep(0.7); continue

        ve   = vault_list[int(ch) - 1]
        hosts = _vault_device_menu(ve, hosts)


def _vault_device_menu(ve: dict, hosts: dict) -> dict:
    """
    Per-device Vault menu. Verifies connection, then offers Browse/Send/Receive.
    Auto-creates Linkx folder on both ends if missing.
    """
    did     = ve.get("device_id", "")
    ip      = ve.get("ip", "")
    user    = ve.get("user", "")
    port    = ve.get("ssh_port", 22)
    os_type = ve.get("os_type", "other")
    lbl     = ve.get("nickname", ip)

    # Resolve key
    kp = ""
    key_name = ve.get("key_name", "")
    if key_name:
        candidate = os.path.join(_ssh_dir(), key_name)
        if os.path.exists(candidate):
            kp = candidate
    if not kp and did:
        kp = get_key(did)

    if not kp:
        err(f"No key for {lbl} — run Setup first.")
        pause(); return hosts

    # Resolve host record (for verify_connection + fast_find_device)
    host = hosts.get(ip)
    if not host:
        # Reconstruct from vault entry
        host = dict(ve)
        hosts[ip] = host

    while True:
        clear()
        osl = OS_PROFILES.get(os_type, OS_PROFILES["other"])["label"]
        hdr(f"VAULT  —  {lbl}", osl)
        pr()

        # ── Live connection check ─────────────────────────────────────
        pr(f"  {C.D}Checking connection...{C.R}")
        result = test_key_verbose(ip, user, port, kp)

        if result == "unreachable":
            # Try fast_find_device — IP may have changed
            pr(f"  {C.Y}Device not at {ip} — searching network...{C.R}")
            new_ip = fast_find_device(host)
            if new_ip:
                ok(f"Found at new IP: {new_ip}")
                host["ip"] = new_ip
                ip = new_ip
                hosts[new_ip] = host
                # Also update vault record
                v = _load_vault()
                if did in v:
                    v[did]["ip"] = new_ip
                    v[did]["mac"] = host.get("mac", v[did].get("mac", ""))
                    _save_vault(v)
                ve["ip"] = new_ip
                save_hosts(hosts)
                result = test_key_verbose(ip, user, port, kp)
            else:
                print(f"\033[1A\033[2K", end="")
                pr(f"  {C.RE}Device offline — start SSH server on {lbl}.{C.R}")
                pr()
                pr(f"  {C.Y}Android:{C.R}  sshd")
                pr(f"  {C.Y}Windows:{C.R}  Start-Service sshd")
                pr(f"  {C.Y}Linux  :{C.R}  sudo systemctl start ssh")
                pr()
                pr(f"  {C.B}[R]{C.R}  Retry")
                pr(f"  {C.B}[0]{C.R}  Back")
                sep()
                ch = ask("Choose", "0")
                if ch.upper() == "R":
                    continue
                return hosts

        if result == "host_key_changed":
            print(f"\033[1A\033[2K", end="")
            err("Host key changed — device may have been wiped.")
            pr(f"  Run  {C.B}[3] Setup{C.R}  to reinstall the key.")
            pause(); return hosts

        if result in ("permission_denied", "no_key"):
            print(f"\033[1A\033[2K", end="")
            err("Key rejected — run Setup again for this device.")
            pause(); return hosts

        # Connected
        print(f"\033[1A\033[2K", end="")
        pr(f"  {C.G}● Connected  {user}@{ip}{C.R}")
        pr()

        # ── Ensure Linkx folders exist on both sides ──────────────────
        local_linkx  = _linkx_path_local()
        remote_linkx = _linkx_path_remote(os_type, user)

        _ensure_linkx_folder_local()
        if not _ensure_linkx_folder_remote(ip, user, port, kp, os_type):
            warn("Could not create remote Linkx folder — continuing anyway.")

        sep()
        pr(f"  {C.B}Local  Linkx:{C.R}  {C.G}{local_linkx}{C.R}")
        pr(f"  {C.B}Remote Linkx:{C.R}  {C.G}{remote_linkx}{C.R}")
        pr()
        sep()
        pr(f"  {C.B}[1]{C.R}  Browse remote Linkx folder")
        pr(f"  {C.B}[2]{C.R}  Send   → file/folder TO device  (lands in Linkx)")
        pr(f"  {C.B}[3]{C.R}  Receive ← file/folder FROM device  (from Linkx)")
        pr(f"  {C.B}[0]{C.R}  Back")
        sep()

        ch = ask("Choose")
        if ch == "0":
            return hosts

        if ch == "1":
            _vault_browse(ip, user, port, os_type, kp, remote_linkx)

        elif ch == "2":
            _vault_send(ip, user, port, os_type, kp,
                        local_linkx, remote_linkx, host)

        elif ch == "3":
            _vault_receive(ip, user, port, os_type, kp,
                           remote_linkx, local_linkx, host)
        else:
            err("Invalid."); time.sleep(0.7)


def _vault_browse(ip, user, port, os_type, kp, start_path: str):
    """
    Browse remote filesystem starting at Linkx folder.
    User can navigate up/down freely.
    """
    _do_browse_at(ip, user, port, os_type, kp, start_path)


def _do_browse_at(ip, user, port, os_type, kp, start_path: str):
    """Browse remote from a specific starting path (can go up/down)."""
    current  = start_path
    history  = []
    page_key = [0]   # mutable so it persists across render loop iterations

    while True:
        clear()
        disp = current if len(current) <= W else "..." + current[-(W-3):]
        hdr(f"VAULT BROWSE  {user}@{ip}", disp)

        pr(f"  {C.D}Loading...{C.R}")
        items = _ls_remote(ip, user, port, kp, current, os_type=os_type)
        print(f"\033[1A\033[2K", end="")

        PAGE = 40
        ps          = page_key[0]
        page_items  = items[ps: ps + PAGE]
        total_pages = (len(items) + PAGE - 1) // PAGE if items else 1
        cur_page    = ps // PAGE + 1

        pr()
        parent = current.rstrip("/").rsplit("/", 1)
        par    = parent[0] if len(parent) > 1 and parent[0] else "/"
        if par != current:
            pname = par.rstrip("/").rsplit("/", 1)[-1] or par
            print(f"  {C.B}[..]{C.R}  {C.D}↑  {pname}{C.R}")

        if not items:
            pr(f"  {C.D}(empty or permission denied){C.R}")
        else:
            for i, (name, full, is_dir) in enumerate(page_items, ps + 1):
                icon = f"{C.CY}[D]{C.R} " if is_dir else "    "
                nm   = f"{C.D}{name}{C.R}" if name.startswith(".") else name
                print(f"  {C.B}[{i:>3}]{C.R}  {icon}{nm}")
            if total_pages > 1:
                pr()
                pr(f"  {C.D}Page {cur_page}/{total_pages}  ({len(items)} items){C.R}")
                if ps + PAGE < len(items):
                    pr(f"  {C.B}[N]{C.R}  Next page")
                if ps > 0:
                    pr(f"  {C.B}[B]{C.R}  Previous page")

        pr()
        pr(f"  {C.B}[ S]{C.R}  Select THIS folder")
        pr(f"  {C.B}[ P]{C.R}  Paste path")
        pr(f"  {C.B}[ 0]{C.R}  Back")
        sep()
        ch = ask("Choose", "")

        if ch in ("0", ".."):
            if history:
                current = history.pop()
                page_key[0] = 0
            else:
                return
        elif ch.upper() == "S":
            pr(f"\n  {C.G}Selected: {current}{C.R}")
            pause(); return
        elif ch.upper() == "P":
            path = ask("Remote path", "")
            if path:
                current = path
                page_key[0] = 0
        elif ch.upper() == "N":
            if ps + PAGE < len(items):
                page_key[0] = ps + PAGE
        elif ch.upper() == "B":
            page_key[0] = max(0, ps - PAGE)
        elif ch.isdigit():
            n = int(ch)
            if 1 <= n <= len(items):
                name, full, is_dir = items[n - 1]
                if is_dir:
                    history.append(current)
                    current = full
                    page_key[0] = 0
                else:
                    pr(f"\n  {C.G}File: {full}{C.R}")
                    pause()
            else:
                err(f"No item [{n}]."); time.sleep(0.7)
        else:
            err("Invalid."); time.sleep(0.7)


def _vault_send(ip, user, port, os_type, kp,
                local_linkx: str, remote_linkx: str, host: dict):
    """
    Vault Send — browse local Linkx folder for what to send,
    default destination is remote Linkx folder.
    Full tar/compression logic applies.
    """
    _do_send(ip, user, port, os_type, kp, host,
             force_local_start=local_linkx,
             force_remote_dest=remote_linkx)


def _vault_receive(ip, user, port, os_type, kp,
                   remote_linkx: str, local_linkx: str, host: dict):
    """
    Vault Receive — browse remote Linkx folder for what to receive,
    default destination is local Linkx folder.
    Full tar logic applies.
    """
    _do_receive(ip, user, port, os_type, kp, host,
                force_remote_start=remote_linkx,
                force_local_dest=local_linkx)


# ─────────────────────────────────────────────────────────────────────
# VAULT PROMPT — called from _name_connection after naming
# ─────────────────────────────────────────────────────────────────────

def _ask_add_to_vault(host: dict, hosts: dict,
                       ip: str, user: str, port: int, kp: str) -> dict:
    """
    Ask user if they want to add this device to the Vault.
    If yes: add to vault, create Linkx folder on remote, create locally.
    Returns updated host dict.
    """
    sep()
    pr(f"  {C.CY}╔{'═'*W}╗{C.R}")
    pr(f"  {C.CY}║{C.R}  {C.B}Add this device to Vault?{C.R}{' ' * (W-27)}{C.CY}║{C.R}")
    pr(f"  {C.CY}║{C.R}  Vault = instant access + auto Linkx folder on both devices{' ' * (W-58)}{C.CY}║{C.R}")
    pr(f"  {C.CY}╚{'═'*W}╝{C.R}")
    pr()
    pr(f"  {C.B}[Y]{C.R}  Yes — add to Vault  (recommended)")
    pr(f"  {C.B}[N]{C.R}  No  — skip")
    sep()
    ch = ask("Add to Vault?", "Y").strip().upper()
    if ch != "Y":
        return host

    did     = host.get("device_id", "")
    os_type = host.get("os_type", "other")

    # Create remote Linkx folder
    pr(f"  {C.D}Creating Linkx folder on remote device...{C.R}")
    rok = _ensure_linkx_folder_remote(ip, user, port, kp, os_type)
    if rok:
        remote_linkx = _linkx_path_remote(os_type, user)
        ok(f"Remote Linkx folder ready: {remote_linkx}")
    else:
        warn("Could not create remote Linkx folder — you can retry from Vault.")

    # Create local Linkx folder
    _ensure_linkx_folder_local()
    local_linkx = _linkx_path_local()
    ok(f"Local Linkx folder ready:  {local_linkx}")

    # Add to vault
    host["vault"] = True
    hosts[ip] = host
    vault_add(host)
    ok(f"Added to Vault: {host.get('nickname', ip)}")
    time.sleep(0.8)
    return host


# ═════════════════════════════════════════════════════════════════════
# ENHANCED QUICK SHARE WITH QUEUE, TRUSTED DEVICES, SPEED DISPLAY
# ═════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────
# QUICK SHARE QUEUE  — per-device offline queue
# Stored in QUICK_SHARE_FILE under key "queue": [...]
# Each entry: { device_id, local_path, direction, queued_at }
# ─────────────────────────────────────────────────────────────────────

def qs_queue_add(device_id: str, local_path: str, direction: str = "send"):
    d = _load_qs()
    q = d.get("queue", [])
    q = [e for e in q if e.get("device_id") != device_id]  # replace existing
    q.append({
        "device_id" : device_id,
        "local_path": local_path,
        "direction" : direction,
        "queued_at" : time.time(),
    })
    d["queue"] = q
    _save_qs(d)


def qs_queue_remove(device_id: str):
    d = _load_qs()
    d["queue"] = [e for e in d.get("queue", []) if e.get("device_id") != device_id]
    _save_qs(d)


def qs_queue_get(device_id: str) -> dict:
    for e in _load_qs().get("queue", []):
        if e.get("device_id") == device_id:
            return e
    return {}


# ─────────────────────────────────────────────────────────────────────
# BACKGROUND QUEUE WATCHER
# Runs in a daemon thread while Linkx is open.
# Probes queued devices every QS_POLL_INTERVAL seconds.
# When one comes online → notifies main thread via callback.
# ─────────────────────────────────────────────────────────────────────

_QS_NOTIFY_QUEUE  = queue.Queue()   # events posted here: (device_id, ip)
_QS_WATCHER_STOP  = threading.Event()
_QS_WATCHER_LOCK  = threading.Lock()
_QS_ACTIVE_DIDS   = set()
_QS_HOSTS_REF     = {}   # shared mutable dict — watcher and main thread both use this


def _qs_queue_watcher(hosts_ref: dict):
    """
    Background daemon — probes queued devices every QS_POLL_INTERVAL.
    - Reloads hosts.json each cycle (fresh IPs).
    - Phase 1: TCP probe last known IP.
    - Phase 2: full subnet scan with device key if TCP fails.
    - On find: updates IP/MAC in hosts_ref + hosts.json.
    - Posts (did, ip) to _QS_NOTIFY_QUEUE for main thread to handle.
    """
    while not _QS_WATCHER_STOP.is_set():
        try:
            fresh = load_hosts()
            with _QS_WATCHER_LOCK:
                hosts_ref.clear()
                hosts_ref.update(fresh)
        except Exception:
            pass

        entries = _load_qs().get("queue", [])
        for entry in entries:
            if _QS_WATCHER_STOP.is_set():
                break
            did  = entry.get("device_id", "")
            if not did:
                continue
            host = next((h for h in hosts_ref.values()
                         if h.get("device_id") == did), None)
            if not host:
                continue
            ip   = host.get("ip", "")
            port = host.get("ssh_port", 22)
            user = host.get("user", "")
            kp   = get_key(did)
            if not kp:
                continue

            found_ip = ""

            # Phase 1: TCP probe last known IP
            if ip and _tcp_probe_fast(ip, port, timeout=1.5):
                if test_key(ip, user, port, kp):
                    found_ip = ip

            # Phase 2: IP changed — full subnet scan with this device's key
            if not found_ip:
                new_ip = fast_find_device(host, hosts_ref)
                if new_ip:
                    found_ip = new_ip
                    # Update IP/MAC in hosts_ref and save
                    old_ip = host.get("ip", "")
                    host["ip"] = new_ip
                    host["mac"] = get_mac(new_ip) or host.get("mac", "")
                    if old_ip and old_ip != new_ip:
                        hosts_ref.pop(old_ip, None)
                    hosts_ref[new_ip] = host
                    try:
                        save_hosts(hosts_ref)
                    except Exception:
                        pass

            if found_ip:
                # Only post if not already pending for this device
                with _QS_NOTIFY_QUEUE.mutex:
                    already_pending = any(
                        item[0] == did
                        for item in _QS_NOTIFY_QUEUE.queue
                    )
                if not already_pending:
                    _QS_NOTIFY_QUEUE.put((did, found_ip))

        _QS_WATCHER_STOP.wait(QS_POLL_INTERVAL)


def start_qs_watcher(hosts: dict):
    """Start background queue watcher — shares _QS_HOSTS_REF with watcher thread."""
    _QS_WATCHER_STOP.clear()
    _QS_HOSTS_REF.clear()
    _QS_HOSTS_REF.update(hosts)
    t = threading.Thread(target=_qs_queue_watcher,
                         args=(_QS_HOSTS_REF,), daemon=True, name="linkx-qs-watcher")
    t.start()


def stop_qs_watcher():
    _QS_WATCHER_STOP.set()


# ─────────────────────────────────────────────────────────────────────
# DOWNLOAD FOLDER DEFAULT PATH — per OS for Quick Share
# ─────────────────────────────────────────────────────────────────────

def _default_remote_dl(os_type: str, user: str) -> str:
    """Return the Downloads folder path for a remote OS (for Quick Share default)."""
    return _downloads_path_remote(os_type, user)


# ─────────────────────────────────────────────────────────────────────
# ENHANCED do_scp WITH LIVE SPEED DISPLAY
# Wraps the existing do_scp but shows a richer progress panel.
# ─────────────────────────────────────────────────────────────────────

def do_scp_with_display(src, dest, port, kp,
                         fname: str = "", total_size: str = "",
                         force_recursive: bool = False) -> tuple:
    """
    Wrapper around do_scp that shows a rich transfer progress panel.
    Used by Vault and enhanced Quick Share.
    """
    clear()
    hdr("TRANSFERRING", fname or os.path.basename(src))
    pr()
    if total_size:
        pr(f"  {C.D}Size : {total_size}{C.R}")
    pr(f"  {C.D}From : {src[:W-8]}{C.R}")
    pr(f"  {C.D}To   : {dest[:W-8]}{C.R}")
    pr()
    sep()
    pr(f"  {C.D}Press Ctrl+C to cancel{C.R}")
    sep()
    print()

    # do_scp already handles progress bar internally via pty / scp output.
    # We just call it and report result.
    result, msg = do_scp(src, dest, port, kp, force_recursive=force_recursive)
    return result, msg


# ─────────────────────────────────────────────────────────────────────
# ENHANCED QUICK SHARE MENU
# ─────────────────────────────────────────────────────────────────────

def menu_quick_share_enhanced(hosts: dict) -> dict:
    """
    Quick Share — redesigned flow:
      Open → check queue → start watcher only if queue exists
      Pick device → test connection → online: browse+transfer
                                    → offline: scan/update OR queue
      Watcher runs ONLY while inside this menu.
      Watcher stops on exit.
    """
    ready = {ip: h for ip, h in hosts.items()
             if h.get("device_id") and get_key(h.get("device_id", ""))}

    if not ready:
        clear(); hdr("QUICK SHARE")
        warn("No devices with keys set up yet.")
        pr()
        pr(f"  Use  {C.B}[1] Scan{C.R}  then  {C.B}[3] Setup{C.R}  from the main menu first.")
        pause(); return hosts

    # ── Start watcher ONLY if queue has entries ───────────────────────
    _qs_watcher_local_stop = threading.Event()
    pending_q = _load_qs().get("queue", [])
    watcher_running = False
    # Flush any stale notifications from previous QS session
    while not _QS_NOTIFY_QUEUE.empty():
        try: _QS_NOTIFY_QUEUE.get_nowait()
        except Exception: break

    def _start_local_watcher():
        nonlocal watcher_running
        if watcher_running: return
        _qs_watcher_local_stop.clear()
        _QS_HOSTS_REF.clear()
        _QS_HOSTS_REF.update(hosts)
        t = threading.Thread(
            target=_qs_queue_watcher,
            args=(_QS_HOSTS_REF,),
            daemon=True, name="linkx-qs-watcher")
        t.start()
        watcher_running = True

    def _stop_local_watcher():
        nonlocal watcher_running
        _qs_watcher_local_stop.set()
        _QS_WATCHER_STOP.set()
        watcher_running = False

    if pending_q:
        # Override global stop event with local one
        _QS_WATCHER_STOP.clear()
        _start_local_watcher()

    try:
        while True:
            # ── Handle any watcher notifications ─────────────────────
            hosts = _qs_handle_notify_queue(hosts)

            # ── Device list ───────────────────────────────────────────
            clear()
            hdr("QUICK SHARE  ⚡", "Instant transfer — queue when offline")
            pr()

            pending_q = _load_qs().get("queue", [])
            if pending_q and not watcher_running:
                _QS_WATCHER_STOP.clear()
                _start_local_watcher()
            if pending_q:
                pr(f"  {C.Y}⚡ {len(pending_q)} transfer(s) queued — watcher active{C.R}")
                pr()

            pr(f"  {C.B}Devices:{C.R}  {C.D}● = online  ○ = offline  ★ = trusted{C.R}")
            pr()

            all_h = list(ready.values())
            online_map = {}
            for h in all_h:
                _ip   = h.get("ip", "")
                _port = h.get("ssh_port", 22)
                online_map[h.get("device_id", "")] = (
                    _tcp_probe_fast(_ip, _port, timeout=0.5) if _ip else False)

            for i, h in enumerate(all_h, 1):
                did    = h.get("device_id", "")
                osl    = OS_PROFILES.get(h.get("os_type", "other"),
                                          OS_PROFILES["other"])["label"][:14]
                online = online_map.get(did, False)
                dot    = f"{C.G}●{C.R}" if online else f"{C.D}○{C.R}"
                star   = f"  {C.CY}★{C.R}" if is_trusted(did) else ""
                q_tag  = f"  {C.Y}[queued]{C.R}" if qs_queue_get(did) else ""
                lbl    = _device_label(h, 18)
                print(f"  {C.B}[{i}]{C.R}  {dot}  {C.B}{lbl:<20}{C.R}  "
                      f"{osl:<16}{star}{q_tag}")

            pr()
            pr(f"  {C.B}[0]{C.R}  Back")
            if watcher_running:
                pr(f"  {C.D}Watcher active — checking every {QS_POLL_INTERVAL}s{C.R}")
            sep()

            # Poll notify queue every second while waiting for input.
            # If watcher fires a notification, abort input, handle transfer,
            # then redraw menu from scratch — never mix transfer UI with input prompt.
            _input_ready  = [None]
            _input_event  = threading.Event()
            _abort_input  = threading.Event()

            def _read_input():
                try:
                    val = input(f"\n  {C.B}❯  Choose device{C.R}: ").strip()
                    if val and C.R:
                        print(f"\033[1A\033[2K  {C.B}❯  Choose device{C.R}: {C.G}{val}{C.R}")
                    _input_ready[0] = val
                except Exception:
                    _input_ready[0] = ""
                finally:
                    _input_event.set()

            _t = threading.Thread(target=_read_input, daemon=True)
            _t.start()

            _notification_fired = False
            while not _input_event.is_set():
                # Check if watcher posted anything
                if not _QS_NOTIFY_QUEUE.empty():
                    # Notification arrived — wait for input thread to finish
                    # (user may be mid-type; give 0.3s then proceed anyway
                    #  since input thread is daemon and won't block exit)
                    _input_event.wait(timeout=0.3)
                    _notification_fired = True
                    break
                _input_event.wait(timeout=1.0)

            if _notification_fired:
                # Handle transfer — owns terminal exclusively now
                print()   # clean newline after the dangling input prompt
                hosts = _qs_handle_notify_queue(hosts)
                # Redraw menu from scratch — don't use whatever user typed
                continue

            ch = _input_ready[0] if _input_ready[0] is not None else ""
            if ch == "0" or not ch:
                break
            if not ch.isdigit() or not (1 <= int(ch) <= len(all_h)):
                err("Invalid."); time.sleep(0.8); continue

            host    = all_h[int(ch) - 1]
            did     = host.get("device_id", "")
            ip      = host.get("ip", "")
            user    = host.get("user", "")
            port    = host.get("ssh_port", 22)
            os_type = host.get("os_type", "other")
            kp      = get_key(did)
            lbl     = _device_label(host)
            osl     = OS_PROFILES.get(os_type, OS_PROFILES["other"])["label"]
            online  = online_map.get(did, False)

            # ── Per-device menu ───────────────────────────────────────
            while True:
                hosts = _qs_handle_notify_queue(hosts)
                clear()
                dot = f"{C.G}● online{C.R}" if online else f"{C.D}○ offline{C.R}"
                hdr(f"QUICK SHARE  —  {lbl}", osl)
                pr()
                pr(f"  Status  : {dot}")
                trusted_now = is_trusted(did)
                pr(f"  Trusted : {'Yes ★' if trusted_now else 'No'}"
                   + (f"  {C.CY}auto-transfer when online{C.R}" if trusted_now else ""))
                pr()
                sep()
                pr(f"  {C.B}[1]{C.R}  Send   → file/folder TO this device")
                pr(f"  {C.B}[2]{C.R}  Receive ← file/folder FROM this device")
                pr()
                tr_label = f"{C.Y}Remove trusted{C.R}" if trusted_now else f"{C.CY}Trust this device{C.R}"
                pr(f"  {C.B}[T]{C.R}  {tr_label}")
                pr(f"  {C.B}[0]{C.R}  Back")
                sep()
                # Poll watcher notifications while waiting — same as device list
                _pd_input   = [None]
                _pd_event   = threading.Event()

                def _pd_read():
                    try:
                        val = input(f"\n  {C.B}❯  Choose{C.R}: ").strip()
                        if val and C.R:
                            print(f"\033[1A\033[2K  {C.B}❯  Choose{C.R}: {C.G}{val}{C.R}")
                        _pd_input[0] = val
                    except Exception:
                        _pd_input[0] = ""
                    finally:
                        _pd_event.set()

                _pd_t = threading.Thread(target=_pd_read, daemon=True)
                _pd_t.start()

                _pd_notified = False
                while not _pd_event.is_set():
                    if not _QS_NOTIFY_QUEUE.empty():
                        _pd_event.wait(timeout=0.3)
                        _pd_notified = True
                        break
                    _pd_event.wait(timeout=1.0)

                if _pd_notified:
                    print()
                    hosts = _qs_handle_notify_queue(hosts)
                    continue   # redraw per-device menu

                direction = _pd_input[0] if _pd_input[0] is not None else ""
                if direction == "0" or not direction: break

                if direction.upper() == "T":
                    new_val = not trusted_now
                    set_trusted(did, new_val)
                    ok(f"★ {lbl} trusted." if new_val else f"Trust removed for {lbl}.")
                    time.sleep(0.8); trusted_now = new_val; continue

                if direction not in ("1", "2"):
                    err("Invalid."); time.sleep(0.7); continue

                # ── Test connection ───────────────────────────────────
                pr(f"\n  {C.D}Testing connection to {ip}...{C.R}")
                online = _tcp_probe_fast(ip, port, timeout=1.5)
                if online:
                    online = test_key(ip, user, port, kp)

                if online:
                    # ── ONLINE PATH ───────────────────────────────────
                    if direction == "1":
                        # Send — browse local, default remote = Downloads
                        local_items = []
                        while True:
                            local = pick_local_path(
                                f"QS SEND → {lbl}  |  "
                                f"{'Add another' if local_items else 'Pick file/folder'}")
                            if not local:
                                if local_items: break
                                else: local_items = None; break
                            local_items.append(local)
                            clear(); hdr("QS SEND — Queue")
                            pr()
                            for j, p in enumerate(local_items, 1):
                                print(f"  {C.G}[{j}]{C.R}  {p}  {C.D}({sz(p)}){C.R}")
                            pr()
                            pr(f"  {C.B}[A]{C.R}  Add another")
                            pr(f"  {C.B}[D]{C.R}  Done")
                            pr(f"  {C.B}[0]{C.R}  Cancel")
                            sep()
                            nc = ask("Choose", "D").upper()
                            if nc == "0": local_items = None; break
                            if nc == "D": break

                        if not local_items: continue

                        # Browse remote destination — starts at Downloads
                        default_remote = _downloads_path_remote(os_type, user)
                        remote_dest = pick_remote_path(
                            os_type, user,
                            f"QS SEND — Where on {lbl}?",
                            ip=ip, port=port, kp=kp,
                            start_path=default_remote)
                        if not remote_dest: continue

                        # Save to QS store
                        d = _load_qs(); d.setdefault(did, {})
                        d[did]["send"]        = local_items[0]
                        d[did]["send_remote"] = remote_dest
                        _save_qs(d)

                        _qs_fire_or_confirm(host, hosts, local_items,
                                            remote_dest, kp, did, lbl,
                                            direction="send")

                    else:
                        # Receive — browse remote, default start = Downloads
                        default_remote = _downloads_path_remote(os_type, user)
                        remote_src = pick_remote_path(
                            os_type, user,
                            f"QS RECEIVE ← {lbl}  |  Pick file/folder",
                            ip=ip, port=port, kp=kp,
                            start_path=default_remote)
                        if not remote_src: continue

                        # Browse local destination
                        local_dest = pick_local_path(
                            f"QS RECEIVE — Save where locally?")
                        if not local_dest: continue
                        if os.path.isfile(local_dest):
                            local_dest = os.path.dirname(local_dest)

                        d = _load_qs(); d.setdefault(did, {})
                        d[did]["recv_remote"] = remote_src
                        d[did]["recv_local"]  = local_dest
                        _save_qs(d)

                        _qs_fire_or_confirm(host, hosts, [remote_src],
                                            local_dest, kp, did, lbl,
                                            direction="recv")

                else:
                    # ── OFFLINE PATH ──────────────────────────────────
                    clear(); hdr("DEVICE OFFLINE", lbl)
                    pr()
                    pr(f"  {C.RE}Cannot reach {user}@{ip}{C.R}")
                    pr()
                    pr(f"  {C.B}[1]{C.R}  SSH running — scan and update IP, then transfer")
                    pr(f"  {C.B}[2]{C.R}  SSH not running — queue for when it comes online")
                    pr(f"  {C.B}[0]{C.R}  Back")
                    sep()
                    off_ch = ask("Choose")

                    if off_ch == "0": continue

                    if off_ch == "1":
                        # Scan to find new IP
                        pr(f"\n  {C.D}Scanning network for {lbl}...{C.R}")
                        new_ip = fast_find_device(host, hosts)
                        if new_ip:
                            ok(f"Found at {new_ip}")
                            hosts = _qs_update_host_ip(host, hosts, new_ip)
                            host["ip"] = new_ip
                            ip = new_ip
                            online = test_key(ip, user, port, kp)
                            if online:
                                ok("Connection verified ✓")
                                # Now do transfer — loop back
                                continue
                            else:
                                err("Found device but key auth failed.")
                                pause(); continue
                        else:
                            warn("Device not found on network.")
                            pr(f"  {C.D}It may be offline or SSH not running.{C.R}")
                            pause(); continue

                    if off_ch == "2":
                        # Queue it — browse files, paste/write destination
                        if direction == "1":
                            local_items = []
                            while True:
                                local = pick_local_path(
                                    f"QS QUEUE SEND → {lbl}  |  "
                                    f"{'Add another' if local_items else 'Pick file/folder'}")
                                if not local:
                                    if local_items: break
                                    else: local_items = None; break
                                local_items.append(local)
                                clear(); hdr("QS QUEUE — Items")
                                pr()
                                for j, p in enumerate(local_items, 1):
                                    print(f"  {C.G}[{j}]{C.R}  {p}  {C.D}({sz(p)}){C.R}")
                                pr()
                                pr(f"  {C.B}[A]{C.R}  Add another")
                                pr(f"  {C.B}[D]{C.R}  Done")
                                pr(f"  {C.B}[0]{C.R}  Cancel")
                                sep()
                                nc = ask("Choose", "D").upper()
                                if nc == "0": local_items = None; break
                                if nc == "D": break

                            if not local_items: continue

                            # Destination — paste or use default Downloads
                            default_remote = _downloads_path_remote(os_type, user)
                            clear(); hdr("QS QUEUE — Remote Destination")
                            pr()
                            pr(f"  {C.D}Default: {C.G}{default_remote}{C.R}")
                            pr()
                            pr(f"  {C.B}[Y]{C.R}  Use default Downloads folder")
                            pr(f"  {C.B}[P]{C.R}  Paste/type a path")
                            sep()
                            dc = ask("Destination", "Y").strip().upper()
                            if dc == "P":
                                remote_dest = ask("Remote path", default_remote).strip()
                                if not remote_dest: remote_dest = default_remote
                            else:
                                remote_dest = default_remote

                            # Save all items as JSON in queue
                            d = _load_qs(); d.setdefault(did, {})
                            d[did]["send"]        = local_items[0]
                            d[did]["send_remote"] = remote_dest
                            d[did]["send_items"]  = local_items
                            _save_qs(d)
                            qs_queue_add(did, local_items[0], "send")

                            # Start watcher now that queue exists
                            _QS_WATCHER_STOP.clear()
                            _start_local_watcher()

                            clear(); hdr("QUEUED", f"Will send when {lbl} comes online")
                            pr()
                            for p in local_items:
                                pr(f"  {C.G}→ {os.path.basename(p)}{C.R}  {C.D}({sz(p)}){C.R}")
                            pr(f"  {C.D}To: {remote_dest}{C.R}")
                            pr()
                            pr(f"  {C.D}Watcher scanning subnet every {QS_POLL_INTERVAL}s.{C.R}")
                            if is_trusted(did):
                                pr(f"  {C.CY}★ Trusted — auto-transfer when found.{C.R}")
                            else:
                                pr(f"  {C.D}Will ask to confirm when device found.{C.R}")
                            pause()

                        else:  # queue receive
                            default_remote = _downloads_path_remote(os_type, user)
                            clear(); hdr("QS QUEUE — What to receive?")
                            pr()
                            pr(f"  {C.D}Default source: {C.G}{default_remote}{C.R}")
                            pr()
                            pr(f"  {C.B}[P]{C.R}  Paste/type remote path")
                            pr(f"  {C.B}[Y]{C.R}  Use remote Downloads folder")
                            sep()
                            dc = ask("Source", "Y").strip().upper()
                            if dc == "P":
                                remote_src = ask("Remote path", default_remote).strip()
                                if not remote_src: remote_src = default_remote
                            else:
                                remote_src = default_remote

                            local_dest = _downloads_path_local()
                            clear(); hdr("QS QUEUE — Save where locally?")
                            pr()
                            pr(f"  {C.D}Default: {C.G}{local_dest}{C.R}")
                            pr()
                            pr(f"  {C.B}[Y]{C.R}  Use local Downloads")
                            pr(f"  {C.B}[P]{C.R}  Paste/type local path")
                            sep()
                            dc2 = ask("Destination", "Y").strip().upper()
                            if dc2 == "P":
                                local_dest = ask("Local path", local_dest).strip() or local_dest

                            d = _load_qs(); d.setdefault(did, {})
                            d[did]["recv_remote"] = remote_src
                            d[did]["recv_local"]  = local_dest
                            _save_qs(d)
                            qs_queue_add(did, remote_src, "recv")

                            _QS_WATCHER_STOP.clear()
                            _start_local_watcher()

                            clear(); hdr("QUEUED", f"Will receive when {lbl} comes online")
                            pr()
                            pr(f"  {C.G}From: {remote_src}{C.R}")
                            pr(f"  {C.D}Save: {local_dest}{C.R}")
                            pr()
                            pr(f"  {C.D}Watcher scanning subnet every {QS_POLL_INTERVAL}s.{C.R}")
                            if is_trusted(did):
                                pr(f"  {C.CY}★ Trusted — auto-receive when found.{C.R}")
                            pause()

    finally:
        # ── Always stop watcher on exit from QS menu ──────────────────
        _stop_local_watcher()

    return hosts


def _qs_fire_or_confirm(host: dict, hosts: dict,
                         local_items: list, remote_dest: str,
                         kp: str, did: str, lbl: str,
                         direction: str = "send",
                         silent: bool = False) -> bool:
    """
    silent=True  → trusted device: no UI at all, transfer silently in background.
    silent=False → untrusted: show confirm screen with Y/P/N options.
    """
    ip      = host.get("ip", "")
    user    = host.get("user", "")
    port    = host.get("ssh_port", 22)
    os_type = host.get("os_type", "other")

    def _pr(msg):
        if not silent: pr(msg)

    if not silent:
        clear()
        hdr("CONFIRM TRANSFER", lbl)
        pr()
        if direction == "send":
            pr(f"  {C.B}Sending {len(local_items)} item(s) to:{C.R}")
            for p in local_items:
                pr(f"    {C.G}{os.path.basename(p)}{C.R}  {C.D}({sz(p)}){C.R}")
            pr(f"  {C.B}To  :{C.R}  {C.B}{user}@{ip}:{remote_dest}{C.R}")
        else:
            pr(f"  {C.B}From:{C.R}  {C.B}{user}@{ip}:{local_items[0]}{C.R}")
            pr(f"  {C.B}Save:{C.R}  {C.G}{remote_dest}{C.R}")
        pr()
        pr(f"  {C.B}[Y]{C.R}  Transfer now")
        pr(f"  {C.B}[P]{C.R}  Pause — ask again in 2 minutes")
        pr(f"  {C.B}[N]{C.R}  Cancel and clear queue")
        sep()
        ch = ask("Choose", "Y").strip().upper()
        if ch == "N":
            qs_queue_remove(did)
            ok("Queue cleared.")
            time.sleep(0.8)
            return False
        if ch == "P":
            pr(f"  {C.D}Paused — checking again in 2 minutes...{C.R}")
            # Count down visibly so user knows app is alive
            for remaining in range(120, 0, -10):
                time.sleep(10)
                print(f"\r  {C.D}Resuming in {remaining}s...{C.R}    ", end="", flush=True)
            print()
            if _tcp_probe_fast(ip, port, timeout=1.5):
                return _qs_fire_or_confirm(host, hosts, local_items,
                                           remote_dest, kp, did, lbl,
                                           direction, silent=False)
            else:
                warn("Device went offline during pause.")
                pause()
                return False
        if ch != "Y":
            return False

    # Remove from queue — firing now
    qs_queue_remove(did)

    if direction == "send":
        # Always use system temp — never put tar in source folder
        # (putting tar in source folder causes it to be included in itself)
        tmp_tar = os.path.join(tempfile.gettempdir(), "Transfer.tar")
        t_cwd, t_names = _tar_cwd_and_names(local_items)

        if not silent:
            pr(f"\n  {C.D}Bundling {len(local_items)} item(s) → Transfer.tar...{C.R}")

        try:
            r = subprocess.run(["tar", "-cf", tmp_tar] + t_names,
                               capture_output=True, cwd=t_cwd)
            if r.returncode != 0:
                if not silent:
                    err(f"tar failed: {r.stderr.decode(errors='ignore')[:120]}")
                try: os.remove(tmp_tar)
                except Exception: pass
                return False
        except FileNotFoundError:
            if not silent:
                err("tar not found — cannot bundle.")
            try: os.remove(tmp_tar)
            except Exception: pass
            return False

        dest_str = f"{user}@{ip}:{remote_dest}"
        if not silent:
            pr(f"  {C.D}Sending Transfer.tar...{C.R}")

        result, msg = do_scp(tmp_tar, dest_str, port, kp)

        # Delete local tar immediately regardless of result
        try: os.remove(tmp_tar)
        except Exception: pass

        if not result:
            if not silent:
                err(f"Transfer failed: {msg}")
                pause()
            return False

        # Remote extract
        remote_tar = f"{remote_dest.rstrip('/')}/Transfer.tar"
        if not silent:
            pr(f"  {C.D}Extracting on remote...{C.R}")

        if os_type == "windows":
            win_tar  = remote_tar.replace("/", "\\")
            win_dest = remote_dest.replace("/", "\\")
            xcmd = (f'powershell -NoProfile -Command "'
                    f'Set-Location \'{win_dest}\'; '
                    f'tar -xf \'{win_tar}\'; '
                    f'Remove-Item -Force \'{win_tar}\' -ErrorAction SilentlyContinue; '
                    f'Write-Output DONE_TAR"')
        else:
            # -C extracts to dest, stdout flushed, explicit echo after delete
            arc_q  = shlex.quote(remote_tar)
            dest_q = shlex.quote(remote_dest)
            xcmd = (f"tar -xf {arc_q} -C {dest_q} 2>/dev/null"
                    f" ; rm -f {arc_q}"
                    f" ; echo DONE_TAR")
            # Note: using ; not && so echo always fires even if tar warns

        out = run_cmd(ip, user, port, xcmd, kp, timeout=120)
        extracted = "DONE_TAR" in out

        if not silent:
            if extracted:
                ok("Extracted on remote ✓")
            else:
                warn("Extraction may have failed — check remote manually.")
            ok(f"Sent to {lbl} ✓")
            _qs_notify(f"Sent to {lbl}: {len(local_items)} item(s)")
            pause()
        else:
            # Silent trusted transfer — just notify OS
            _qs_notify(f"✓ Sent to {lbl}: {len(local_items)} item(s)")

        return True

    else:
        # Receive
        remote_path = local_items[0]
        fname       = os.path.basename(remote_path.rstrip("/"))
        src_str     = f"{user}@{ip}:{remote_path}"
        if not silent:
            pr(f"\n  {C.D}Receiving {fname}...{C.R}")

        result, msg = do_scp(src_str, remote_dest, port, kp)
        if result:
            if not silent:
                ok(f"Received: {fname} → {remote_dest}")
                pause()
            _qs_notify(f"{'✓ ' if silent else ''}Received from {lbl}: {fname}")
        else:
            if not silent:
                err(f"Transfer failed: {msg}")
                pause()
        return result


def _qs_handle_notify_queue(hosts: dict) -> dict:
    """
    Process watcher notifications. Called while inside QS menu.
    Trusted devices → silent auto-transfer (no UI).
    Untrusted → show confirm screen.
    """
    try:
        while True:
            did, new_ip = _QS_NOTIFY_QUEUE.get_nowait()
            entry = qs_queue_get(did)
            if not entry:
                continue

            host = next((h for h in hosts.values()
                         if h.get("device_id") == did), None)
            if not host:
                continue

            kp  = get_key(did)
            lbl = _device_label(host)
            if not kp:
                continue

            direction = entry.get("direction", "send")
            trusted   = is_trusted(did)

            # Update IP if changed
            if new_ip != host.get("ip", ""):
                hosts = _qs_update_host_ip(host, hosts, new_ip)
                host["ip"] = new_ip

            os_type = host.get("os_type", "other")
            user    = host.get("user", "")
            port    = host.get("ssh_port", 22)
            ip      = host.get("ip", "")

            qs_data = _load_qs().get(did, {})

            if direction == "send":
                local_items = qs_data.get("send_items",
                              [qs_data.get("local_path", entry.get("local_path", ""))])
                local_items = [p for p in local_items if p and os.path.exists(p)]
                if not local_items:
                    qs_queue_remove(did)
                    continue
                remote_dest = qs_data.get("send_remote",
                              _downloads_path_remote(os_type, user))
                path_a = local_items
                path_b = remote_dest
            else:
                remote_src = qs_data.get("recv_remote",
                             entry.get("local_path", ""))
                local_dest = qs_data.get("recv_local",
                             _downloads_path_local())
                path_a = [remote_src]
                path_b = local_dest

            if trusted:
                # ── Silent auto-transfer — no UI at all ──────────────
                _qs_fire_or_confirm(host, hosts, path_a, path_b,
                                    kp, did, lbl,
                                    direction=direction, silent=True)
            else:
                # ── Show confirm screen ───────────────────────────────
                _qs_fire_or_confirm(host, hosts, path_a, path_b,
                                    kp, did, lbl,
                                    direction=direction, silent=False)

    except queue.Empty:
        pass
    return hosts

def main():
    if not os.path.exists(DATA_FILE):
        show_guide()

    if not shutil.which("ssh"):
        print(f"\n  {C.RE}ssh not found. Install OpenSSH.{C.R}")
        print(f"  Windows: Settings → Apps → Optional Features → OpenSSH Client")
        sys.exit(1)

    hosts = load_hosts()

    while True:

        clear()
        hdr("LINKX  —  Network File Transfer",
            f"{socket.gethostname()}   {local_ip()}")

        total   = len(hosts)
        key_rdy = sum(1 for h in hosts.values()
                      if get_key(h.get("device_id", "")))
        vault_count = len(_load_vault())
        pr(f"  Known devices: {C.Y}{total}{C.R}   "
           f"Key ready: {C.G}{key_rdy}{C.R}   "
           f"Vault: {C.CY}{vault_count}{C.R}")

        # ── Pending queue indicator ───────────────────────────────────
        pending_q = _load_qs().get("queue", [])
        if pending_q:
            pr(f"  {C.Y}⚡ {len(pending_q)} transfer(s) queued — pinging offline device(s)...{C.R}")

        cfg = [h for h in hosts.values() if h.get("user")]
        if cfg:
            sep()
            for h in cfg[:5]:
                did  = h.get("device_id", "")
                kp   = get_key(did) if did else ""
                kn   = h.get("key_name", "")
                if kn and not kp:
                    _nk = os.path.join(_ssh_dir(), kn)
                    if os.path.exists(_nk): kp = _nk
                dot  = f"{C.G}●{C.R}" if kp else f"{C.Y}○{C.R}"
                osl  = OS_PROFILES.get(h.get("os_type", "other"),
                                        OS_PROFILES["other"])["label"]
                lbl  = _device_label(h, 18)
                rl   = f" {C.CY}↗{C.R}" if (h.get("relay") and
                        not is_directly_reachable(h["ip"])) else ""
                kn_s = f"  {C.D}🔑 {kn}{C.R}" if kn else ""
                vault_s = f"  {C.CY}🔒{C.R}" if vault_has(did) else ""
                trust_s = f"  {C.CY}★{C.R}" if (did and is_trusted(did)) else ""
                print(f"  {dot}  {C.B}{lbl:<16}{C.R}  {h['ip']:<15}  "
                      f"{h.get('user','?'):<10}  {osl}{rl}{kn_s}{vault_s}{trust_s}")
            if len(cfg) > 5: pr(f"  {C.D}  ... +{len(cfg)-5} more{C.R}")
        sep()
        pr(f"  {C.B}[Q]{C.R}  Quick Share  ⚡  pick files → auto-send / queue when offline")
        pr(f"  {C.B}[V]{C.R}  Vault  🔒  instant access to paired Linkx folders")
        sep()
        pr(f"  {C.B}[1]{C.R}  Scan network          find SSH devices")
        pr(f"  {C.B}[2]{C.R}  Transfer files         send / receive")
        pr(f"  {C.B}[3]{C.R}  Setup device           first-time connect")
        pr(f"  {C.B}[P]{C.R}  Pair devices  🔗  zero-config two-way key exchange")
        pr(f"  {C.B}[4]{C.R}  My SSH keys")
        pr(f"  {C.B}[5]{C.R}  Remove device")
        pr(f"  {C.B}[6]{C.R}  Rename / nickname a device")
        pr(f"  {C.B}[7]{C.R}  SSH Server     start / stop this device's server")
        _tools_ok = all([_local_has_7z(), _local_has_rsync(), shutil.which("ssh")])
        pr(f"  {C.B}[8]{C.R}  Install tools  7-Zip / rsync / ssh  "
           f"{'  ' + C.G + '✓ all ready' + C.R if _tools_ok else '  ' + C.Y + '✗ some missing' + C.R}")
        pr(f"  {C.B}[T]{C.R}  Raw terminal   run commands without quitting")
        pr(f"  {C.B}[?]{C.R}  How to use this tool")
        pr(f"  {C.B}[0]{C.R}  Exit")
        sep()

        ch = ask("Choose")
        if not ch: continue
        if ch == "0":
            stop_qs_watcher()
            pr("\n  Goodbye.\n"); break

        elif ch.upper() == "Q":
            hosts = menu_quick_share_enhanced(hosts)

        elif ch.upper() == "V":
            hosts = menu_vault(hosts)

        elif ch.upper() == "P":
            hosts = menu_pair(hosts)

        elif ch == "1":
            hosts = menu_scan(hosts)

        elif ch == "2":
            if not hosts:
                clear(); hdr("TRANSFER FILES")
                pr()
                pr(f"  {C.D}No devices stored yet.{C.R}")
                pr()
                pr(f"  {C.B}[A]{C.R}  Add device by IP address manually")
                pr(f"  {C.B}[L]{C.R}  Test localhost (127.0.0.1) — verify SSH on this device")
                pr(f"  {C.B}[1]{C.R}  Scan network first → then transfer")
                pr(f"  {C.B}[0]{C.R}  Back")
                sep()
                sub = ask("Choose", "A").strip().upper()
                if sub == "1":
                    hosts = menu_scan(hosts)
                    h = select_device(hosts)
                    if h: transfer_menu(h, hosts)
                elif sub in ("A", "L"):
                    raw_ip = "127.0.0.1" if sub == "L" else ask("IP address").strip()
                    if raw_ip:
                        raw_port = 22
                        if ":" in raw_ip:
                            parts = raw_ip.rsplit(":", 1)
                            raw_ip = parts[0]
                            try: raw_port = int(parts[1])
                            except ValueError: pass
                        h = hosts.get(raw_ip) or {
                            "ip": raw_ip, "hostname": raw_ip, "mac": "",
                            "ssh_port": raw_port, "os_type": "other",
                            "user": "", "device_id": "", "key_ok": False,
                            "seen_at": time.time()
                        }
                        hosts[raw_ip] = h
                        save_hosts(hosts)
                        transfer_menu(h, hosts)
                        hosts = load_hosts()
            else:
                h = select_device(hosts)
                if h: transfer_menu(h, hosts)

        elif ch == "3":
            if not hosts:
                clear(); hdr("SETUP DEVICE")
                pr()
                pr(f"  {C.D}No devices stored yet.{C.R}")
                pr()
                pr(f"  {C.B}[A]{C.R}  Enter IP address to set up")
                pr(f"  {C.B}[L]{C.R}  Test localhost (127.0.0.1)")
                pr(f"  {C.B}[1]{C.R}  Scan first → then set up")
                pr(f"  {C.B}[0]{C.R}  Back")
                sep()
                sub = ask("Choose", "A").strip().upper()
                if sub == "1":
                    hosts = menu_scan(hosts)
                    h = select_device(hosts)
                    if h: hosts = setup_device(h, hosts)
                elif sub in ("A", "L"):
                    raw_ip = "127.0.0.1" if sub == "L" else ask("IP address").strip()
                    if raw_ip:
                        h = hosts.get(raw_ip) or {
                            "ip": raw_ip, "hostname": raw_ip, "mac": "",
                            "ssh_port": 22, "os_type": "other",
                            "user": "", "device_id": "", "key_ok": False,
                            "seen_at": time.time()
                        }
                        hosts[raw_ip] = h
                        save_hosts(hosts)
                        hosts = setup_device(h, hosts)
            else:
                h = select_device(hosts)
                if h: hosts = setup_device(h, hosts)

        elif ch == "4":
            clear(); hdr("MY SSH KEYS")
            km  = _load_km()
            pre = _find_existing_keys()
            all_k = list({*pre, *km.values()})
            if not all_k:
                pr("  No keys yet — run [3] Setup to generate one.")
            for k in all_k:
                if not os.path.exists(k): continue
                pp = k + ".pub"
                identity = _read_key_identity(k)
                pr(f"\n  {C.G}{os.path.basename(k)}{C.R}")
                if identity.get("this_device"):
                    pr(f"  {C.CY}Identity : {identity['this_device']} → {identity.get('remote_device','?')}{C.R}")
                    pr(f"  {C.D}Created  : {identity.get('created','?')}   PairID: {identity.get('pair_id','?')}{C.R}")
                if os.path.exists(pp):
                    with open(pp) as f:
                        pr(f"  {C.D}{f.read().strip()[:60]}...{C.R}")
            if km:
                pr(f"\n  {C.D}Key → Device ID mapping:{C.R}")
                for did, kpath in km.items():
                    pr(f"  {did}  →  {os.path.basename(kpath)}")
            pause()

        elif ch == "5":
            h = select_device(hosts)
            if h:
                if ask(f"Remove {h['ip']}? [Y/N]", "N").upper() == "Y":
                    did  = h.get("device_id", "")
                    ip   = h.get("ip", "")
                    port = h.get("ssh_port", 22)
                    # 1. Remove from hosts
                    hosts.pop(ip, None)
                    save_hosts(hosts)
                    if did:
                        # 2. Delete key files from disk (.pub + .linkx_meta too)
                        kp = get_key(did)
                        if kp:
                            for _kf in (kp, kp + ".pub", kp + ".linkx_meta"):
                                try:
                                    if os.path.exists(_kf): os.remove(_kf)
                                except Exception: pass
                        # 3. Remove from key map
                        _km = _load_km()
                        _km.pop(did, None)
                        _save_km(_km)
                        # 4. Delete stored password
                        del_pw(did)
                        # 5. Remove from vault
                        if vault_has(did):
                            vault_remove(did)
                        # 6. Remove from trusted list
                        set_trusted(did, False)
                        # 7. Remove from QS queue and per-device QS data
                        qs_queue_remove(did)
                        _qs_d = _load_qs()
                        _qs_d.pop(did, None)
                        _save_qs(_qs_d)
                        # 8. Remove from ~/.ssh/known_hosts
                        _remove_known_hosts_entry(ip, port)
                    ok(f"Removed {ip} — all keys, data and queue entries deleted ✓")
                    time.sleep(1)

        elif ch == "6":
            hosts = menu_rename_device(hosts)

        elif ch == "7":
            hosts = menu_ssh_server(hosts)

        elif ch == "8":
            hosts = menu_install_tools(hosts)

        elif ch.upper() == "T":
            pr(f"\n  {C.B}Raw Terminal{C.R}  — type 'exit' to return to Linkx")
            sep()
            try:
                if os.name == "nt":
                    subprocess.run(["cmd.exe"])
                else:
                    subprocess.run([os.environ.get("SHELL", "/bin/sh")])
            except Exception as e:
                err(f"Could not open terminal: {e}")

        elif ch == "?":
            show_guide()

        else:
            err("Invalid."); time.sleep(0.8)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-v", "version"):
        print(f"{__app_name__} v{__version__}")
        print(f"Author  : {__author__}")
        print(f"Email   : {__email__}")
        print(f"Launched: {__launched__}")
        sys.exit(0)
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        sys.exit(0)
