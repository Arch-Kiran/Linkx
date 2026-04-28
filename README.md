# LInkx

> Transfer files between any devices on your network at full native speed with full potential of hardware and OS with help of SSH — no cloud, no accounts, no bullshit.

**Version:** 1.0.0.0 &nbsp;|&nbsp; **Author:** Kiran Pradeep Malik &nbsp;|&nbsp; **License:** MIT
**Contact:** sysarch.kiran@gmail.com &nbsp;|&nbsp; **Instagram:** [@kiran_0807x](https://www.instagram.com/kiran_0807x?igsh=MWZtaTcyMGg5ODkzbw==)

---

## What is LInkx?

LInkx is a **single Python file** that transfers files between any devices on your local network using SSH. No internet. No cloud accounts. No installation. Just run it.

**How it works under the hood:**
LInkx is a command factory. It figures out the correct `scp`/`rsync`/`ssh` command for your situation, fires it, and steps aside completely. Python never touches your data in transit — the OS handles the transfer natively at full hardware speed. What you see in the terminal is the actual `scp` command running, not a wrapper.

---

## Platform Support

| Platform | Send | Receive | SSH Port | Notes |
|---|---|---|---|---|
| Linux (all distros) | ✅ | ✅ | 22 | Full support |
| Android / Termux | ✅ | ✅ | 8022 | Full support |
| macOS | ✅ | ✅ | 22 | Full support |
| Windows 10 / 11 | ✅ | ✅ | 22 | OpenSSH required |
| Windows 7 / 8 | ⚠️ | ⚠️ | 22 | Manual Win32-OpenSSH install |
| iOS | ❌ | ❌ | — | No SSH server without jailbreak |

---

## Requirements

- **Python 3.12+** recommended (tested on 3.12.7)
- **`ssh` and `scp`** on PATH (OpenSSH client)
- **SSH server running** on the target device
- Both devices on the **same network** (WiFi / hotspot / USB tether / LAN)
- No pip installs. Zero external dependencies. stdlib only.

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Arch-Kiran/Linkx.git
cd Linkx

# Run
python3 linkx.py          # Linux / macOS / Android (Termux)
python  linkx.py          # Windows

# Version info
python3 linkx.py --version
```

First run automatically opens the user guide.

---

## How to Use — Full Walkthrough

Every step below shows exactly what the terminal looks like at that stage.

---

### Home Screen

The main menu shows all known devices and their status at a glance.
`●` = online, `○` = offline, `🔑` = key ready, `🔒` = in Vault, `★` = trusted (Quick Share auto-transfer).

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                LINKX  —  Network File Transfer                 ║
  ║                      V-15   192.168.100.1                      ║
  ╚════════════════════════════════════════════════════════════════╝
    Known devices: 5   Key ready: 2   Vault: 1
    ⚡ 1 transfer(s) queued — pinging offline device(s)...
  ────────────────────────────────────────────────────────────────
  ●  Vivo              10.100.83.199    u0_a226     Android / Termux  🔑 V-15_to_Vivo  ★
  ●  Kali              192.168.45.150   kira        Linux  🔑 V-15_to_Kali  🔒
  ────────────────────────────────────────────────────────────────
    [Q]  Quick Share  ⚡  pick files → auto-send / queue when offline
    [V]  Vault  🔒  instant access to paired Linkx folders
  ────────────────────────────────────────────────────────────────
    [1]  Scan network          find SSH devices
    [2]  Transfer files         send / receive
    [3]  Setup device           first-time connect
    [P]  Pair devices  🔗  zero-config two-way key exchange
    [4]  My SSH keys
    [5]  Remove device
    [6]  Rename / nickname a device
    [7]  SSH Server     start / stop this device's server
    [8]  Install tools  7-Zip / rsync / ssh    ✓ all ready
    [T]  Raw terminal   run commands without quitting
    [?]  How to use this tool
    [0]  Exit
  ────────────────────────────────────────────────────────────────
  ❯  Choose:
```

---

### Step 1 — Start SSH on the Target Device

Before LInkx can reach another device, that device needs its SSH server running.
Use `[7] SSH Server` to start/stop SSH on **your** device. For the **target** device, use the commands below.

**Android / Termux:**
```bash
pkg install openssh    # first time only
passwd                 # set a password (first time)
sshd                   # starts SSH on port 8022
```

**Windows 10 / 11:**
```
Settings → Apps → Optional Features → Add → OpenSSH Server
Then: Start-Service sshd   (PowerShell as Admin)
Or use [7] SSH Server in LInkx — it handles everything automatically
```

**Linux (Debian / Ubuntu / Kali / Mint):**
```bash
sudo apt install openssh-server   # first time only
sudo systemctl start ssh
```

**macOS:**
```
System Settings → General → Sharing → Remote Login → ON
```

---

### Step 2 — Scan the Network `[1]`

LInkx scans your local network and finds every device with SSH open. No IP entry needed.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                        SCANNING NETWORK                        ║
  ╚════════════════════════════════════════════════════════════════╝

  Detecting subnets...

  Scan strategy :

    Phase 1  → Stored devices (last known IP + MAC)  [instant]
    Phase 2  → Full subnet scan  192.168.100.x, 192.168.45.x, 10.100.83.x
    5 stored device(s) — Phase 1 probes these first

    Ports : 22 (Linux/Win/Mac)  8022 (Android/Termux)
    Speed : 1.2s/host  |  200 threads  |  ports 22+8022 parallel
  ────────────────────────────────────────────────────────────────
    Devices appear live as found. Type number + Enter to jump.
    Ctrl+C to cancel.
  ────────────────────────────────────────────────────────────────
  FOUND [1]  192.168.45.162    :8022  MAC:be:5f:d9:1f:6d:6b  Android
         → type 1 + Enter to jump there now
  ❯  Device number (or Enter when done):
  ────────────────────────────────────────────────────────────────
  Found 1 SSH device(s) in 10.5s
  ────────────────────────────────────────────────────────────────
    Go to a device now?

  [ 1]  Vivo                  192.168.45.162    Android / Termux  Setup needed

    [R]  Rename a device
    [0]  Back to main menu
  ────────────────────────────────────────────────────────────────
  ❯  Choose:
```

**How the scanner works under the hood:**
- Phase 1 probes all known devices simultaneously using their last known IP (~0.5s total)
- Phase 2 blasts the full subnet with OS-aware thread count (100–300 threads depending on OS)
- Both port 22 and 8022 are probed in parallel per IP — worst case 1.2s per host
- Banner grab identifies OS from SSH handshake (no auth needed)
- Devices with changed IPs are re-identified by their stored SSH key fingerprint

---

### Step 3 — First-Time Connect: Setup `[3]` or Pair `[P]`

#### Option A — Setup (you know the other device's password)

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                  SETUP — 192.168.45.162                        ║
  ║                       (unknown)                                ║
  ╚════════════════════════════════════════════════════════════════╝

  Detecting remote OS from SSH banner...
  Detected: android

  What OS is on 192.168.45.162?

  [1]  Android / Termux              port 8022  ← detected
  [2]  Linux — Debian/Ubuntu/Mint    port 22
  [w]  Windows 10/11 (OpenSSH)       port 22
  ...

  ❯  OS type [1]:

  Remote username
  (run 'whoami' in Termux → e.g. u0_a226)

  ❯  Username []:

  SSH will ask for the password of u0_a226@192.168.45.162
  Type it when prompted (characters are hidden).

  [password entered once — key installed automatically]

  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Key login confirmed — u0_a226@192.168.45.162             │
  └──────────────────────────────────────────────────────────────┘
  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Passwordless connection established!                      │
  └──────────────────────────────────────────────────────────────┘
```

After setup, LInkx asks you to name both devices:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                    NAME THIS CONNECTION                        ║
  ║               Give both devices a friendly name                ║
  ╚════════════════════════════════════════════════════════════════╝

  This device   (the one you are using now):
  ❯  Your device name [V-15]: V-15

  Other device  (192.168.45.162):
  ❯  Other device name [u0_a226]: Vivo

  Renaming key:  V-15_to_Vivo

  ✓  Key renamed: V-15_to_Vivo
  ✓  Identity: Vivo remembered by key — survives IP/MAC changes
```

The key file `V-15_to_Vivo` is now permanent. If the phone changes IP or MAC address, LInkx finds it by trying this key against every device on the subnet — the first one that accepts it is Vivo.

#### Option B — Zero-Config Pair `[P]` (no password needed)

Both devices run LInkx. One chooses HOST, one chooses CLIENT. A 6-digit PIN confirms the correct devices are pairing. Keys are exchanged both ways automatically.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                ZERO-CONFIG PAIRING                             ║
  ║          Pair two devices running linkx.py                     ║
  ╚════════════════════════════════════════════════════════════════╝

  [1]  HOST   — I am the device others connect TO
               SSH server will start automatically
  [2]  CLIENT — I will find and connect to the HOST

  ❯  Choose:
```

**HOST side** shows a PIN:
```
    PIN — CLIENT must confirm this matches:

  ╔════════════════════╗
  ║   482917            ║
  ╚════════════════════╝

  Pairing server running on port 55222...
  CLIENT is scanning the LAN to find us...
```

**CLIENT side** finds HOST and confirms PIN:
```
  ╔════════════════════════════════════════════════════════════════╗
  ║             PAIRING — CLIENT MODE  HOST found: V-15            ║
  ╚════════════════════════════════════════════════════════════════╝

  HOST device:
    IP       : 192.168.100.1
    Hostname : V-15
    SSH port : 22

  Confirm PIN matches HOST screen:

  ╔════════════════════╗
  ║   482917            ║
  ╚════════════════════╝

  [Y]  PIN matches — pair now
  [N]  Wrong device — cancel
```

Result: both devices can SSH to each other. No password. Ever again.

---

### Step 4 — Transfer Files `[2]`

```
  ╔════════════════════════════════════════════════════════════════╗
  ║             TRANSFER  u0_a226@10.100.83.199:8022               ║
  ║                      Android / Termux  Vivo                    ║
  ╚════════════════════════════════════════════════════════════════╝
    Key  : V-15_to_Vivo
    MAC  : 12:5f:43:0e:dd:04   ID: 43af72be
    Phone storage: /storage/emulated/0/

  ────────────────────────────────────────────────────────────────
    [1]  Send     →  file or folder TO this device
    [2]  Receive  ←  file or folder FROM this device
    [3]  Browse remote files
    [4]  Run command on remote
    [5]  Open SSH shell  (full terminal on REMOTE)
    [S]  Share Linkx  →  send this app to device
    [T]  Raw local terminal  (run commands HERE without quitting)
    [X]  Tar threshold : 10 files  (tar when count exceeds this)
  ────────────────────────────────────────────────────────────────
    [6]  Re-setup  (change user / reinstall key)
    [V]  🔒 In Vault  (already added)
    [0]  Back
  ────────────────────────────────────────────────────────────────
  ❯  Choose:
```

#### Send `[1]`

Pick files one by one. For each item, choose to compress or not:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║              SEND — Queue    2 item(s) selected                ║
  ╚════════════════════════════════════════════════════════════════╝

  [ 1]  /home/kira/Books  (folder — 47 files)  → Books.7z  [.7z]
  [ 2]  /home/kira/notes.pdf  (1.2MB)          ← just picked

  Compress this item with 7-Zip?
  [Y]  Yes — compress into .7z
  [N]  No  — send raw

  ❯  Compress? [N]:

  [A]  Add another item
  [D]  Done — proceed to send
  [0]  Cancel everything
  ❯  Choose [D]:
```

Then live-browse the remote device to pick a destination:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║     SEND → u0_a226@10.100.83.199  |  Where on device?         ║
  ║       Live browser — u0_a226@10.100.83.199  [Android / Termux] ║
  ╚════════════════════════════════════════════════════════════════╝

    Locations:

  [ 1]  Termux Home (~)              /data/data/com.termux/files/home
  [ 2]  Downloads  (symlink)         ~/storage/downloads
  [ 3]  Internal Storage (symlink)   ~/storage/shared
  [ 4]  DCIM / Camera (symlink)      ~/storage/dcim
  ...

    [P]  Paste path directly
    [0]  Back
  ❯  Choose:
```

LInkx then checks if those items already exist at the destination:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                   CHECKING DESTINATION                         ║
  ╚════════════════════════════════════════════════════════════════╝

  Checking if items already exist on remote...

  These items already exist at destination:
    • Books.7z

  rsync not found on: remote device

  [1]  Install rsync on missing device(s) then use rsync
  [2]  Skip rsync — overwrite existing files
  [3]  Skip rsync — send to 'Copy' subfolder
  [0]  Cancel
  ❯  Choose [1]:
```

If file count exceeds the tar threshold, items are bundled:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║            PREPARING   Building Transfer.tar  (2 items)        ║
  ╚════════════════════════════════════════════════════════════════╝

  Total files: 48  (threshold: 10)

  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Transfer.tar ready  (18.4MB)                             │
  └──────────────────────────────────────────────────────────────┘
```

Transfer fires — progress bar shown:

```
  → Transfer.tar

  Transferring: Transfer.tar
  [»»»»»»»»»»»»»»»»»»»»»»»»»»»»]  100%  4.2MB/s  ETA 0:00

  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Transferred!                                             │
  └──────────────────────────────────────────────────────────────┘

  Extracting Transfer.tar on remote...
  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Transfer.tar extracted and deleted on remote ✓           │
  └──────────────────────────────────────────────────────────────┘

  Decompress .7z file(s) on remote device?
    • Books.7z
  [Y]  Yes — extract and delete .7z files on remote
  [N]  No  — leave .7z as-is
  ❯  Decompress on remote? [Y]:
```

#### Tar Threshold `[X]`

Control when files get bundled into a tar archive:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║              TAR THRESHOLD                                     ║
  ║         When to bundle files into Transfer.tar                 ║
  ╚════════════════════════════════════════════════════════════════╝

  Current threshold:  10 files

  If total file count across selected items exceeds
  this number, they are bundled into Transfer.tar.
  Single files are NEVER tarred regardless of size.

  Examples:
    0  = always tar (except single files)
    10 = tar only when count > 10  (default)
    99 = almost never tar

  ❯  New threshold (Enter to keep current) [10]:
```

---

### Step 5 — Vault `[V]`

Vault is a curated list of devices you transfer with regularly. Each Vault device gets a shared `Linkx/` folder in Downloads on both devices.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                      LINKX VAULT                               ║
  ║                  Your trusted device library                   ║
  ╚════════════════════════════════════════════════════════════════╝

  [ 1]  ●  Vivo                Android / Termux
  [ 2]  ○  Kali                Linux

  ────────────────────────────────────────────────────────────────
  ● = online now  ○ = offline
  ❯  Choose device:
```

Inside a Vault device:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                     VAULT  —  Vivo                             ║
  ║                    Android / Termux                            ║
  ╚════════════════════════════════════════════════════════════════╝

  ● Connected  u0_a226@10.100.83.199

  Local  Linkx:   /home/kira/Downloads/Linkx
  Remote Linkx:   /sdcard/Download/Linkx

  ────────────────────────────────────────────────────────────────
  [1]  Browse remote Linkx folder
  [2]  Send   → file/folder TO device  (lands in Linkx)
  [3]  Receive ← file/folder FROM device  (from Linkx)
  [0]  Back
  ❯  Choose:
```

---

### Step 6 — Quick Share `[Q]`

Pick files first. Transfer fires automatically when the device comes online.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                  QUICK SHARE  ⚡                               ║
  ║       Instant transfer — queue when offline                    ║
  ╚════════════════════════════════════════════════════════════════╝

  Devices:  ● = online  ○ = offline  ★ = trusted

  [ 1]  ●  Vivo                Android / Termux    ★
  [ 2]  ○  Kali                Linux        [queued]

  [0]  Back
  ❯  Choose device:
```

**Online device** — browse and transfer immediately:
```
  ╔════════════════════════════════════════════════════════════════╗
  ║              QUICK SHARE  —  Vivo                              ║
  ║                    Android / Termux                            ║
  ╚════════════════════════════════════════════════════════════════╝

  Status  : ● online
  Trusted : Yes ★  auto-transfer when online

  [1]  Send   → file/folder TO this device
  [2]  Receive ← file/folder FROM this device

  [T]  Remove trusted  (stop auto-transfer)
  [0]  Back
  ❯  Choose:
```

**Offline device** — choose what happens:
```
  ╔════════════════════════════════════════════════════════════════╗
  ║                   DEVICE OFFLINE — Kali                        ║
  ╚════════════════════════════════════════════════════════════════╝

  Cannot reach kira@192.168.45.150

  [1]  SSH running — scan and update IP, then transfer
  [2]  SSH not running — queue for when it comes online
  [0]  Back
  ❯  Choose:
```

**Queued transfer notification** — fires automatically:
```
  ╔════════════════════════════════════════════════════════════════╗
  ║                    DEVICE ONLINE! — Kali                       ║
  ╚════════════════════════════════════════════════════════════════╝

  ● Kali found at 192.168.45.150

  Queued: send 2 item(s) → /home/kira/Downloads

  CONFIRM TRANSFER — Kali
  Sending 2 item(s) to:
    Books.7z  (18.4MB)
    notes.pdf  (1.2MB)
  To  :  kira@192.168.45.150:/home/kira/Downloads

  [Y]  Transfer now
  [P]  Pause — ask again in 2 minutes
  [N]  Cancel and clear queue
  ❯  Choose [Y]:
```

For **trusted devices**, this entire confirmation is skipped — transfer fires silently with an OS notification.

---

### Step 7 — Install Tools `[8]`

LInkx detects what's installed and offers to install anything missing:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                       INSTALL TOOLS                            ║
  ║              Install transfer tools on this device             ║
  ╚════════════════════════════════════════════════════════════════╝

  7-Zip : ✓  installed
  rsync : ✗  optional — transfers work without it (scp fallback active)
  ssh   : ✓  installed
  tar   : ✓  installed

  [1]  Install / upgrade  7-Zip
  [2]  Install / upgrade  rsync
  [3]  Install / upgrade  openssh
  [0]  Back
  ❯  Choose:
```

**7-Zip** — compress items before sending. Installed automatically per OS (apt / dnf / pacman / brew / winget + MSYS2).

**rsync** — delta transfers. Only sends changed bytes when a file already exists at destination. Works between Linux↔Linux, Linux↔Android, Linux↔macOS. Windows uses scp fallback.

---

### SSH Server Manager `[7]`

Start or stop the SSH server on **this device** with one keypress. LInkx detects your OS and runs the correct command. On Windows it also manages firewall rules automatically.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                  SSH SERVER MANAGER                            ║
  ║                This device: Kali Linux                         ║
  ╚════════════════════════════════════════════════════════════════╝

  Status : ● RUNNING  (port 22)

  [1]  Stop SSH server
  [2]  Show start commands  (for all OS)
  [3]  Show stop  commands  (for all OS)
  [0]  Back
  ❯  Choose:
```

---

### Share LInkx `[S]`

Send `linkx.py` itself to another device. It creates `Downloads/Linkx/Linkx app/linkx.py` on the remote and shows the exact command to run it.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                       SHARE LINKX                              ║
  ║              Send this app → u0_a226@10.100.83.199             ║
  ╚════════════════════════════════════════════════════════════════╝

  This script:  /home/kira/tools/linkx.py
  Size       :  420KB
  Destination:  u0_a226@10.100.83.199:~/storage/downloads/Linkx/Linkx app

  [Y]  Send now
  [0]  Cancel
  ❯  Choose [Y]:

  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Linkx sent to u0_a226@10.100.83.199 ✓                   │
  └──────────────────────────────────────────────────────────────┘

  To run Linkx on the remote device:
  Android / Termux:
    cd ~/storage/downloads/Linkx/Linkx\ app
    python linkx.py
```

---

## Device Identity — How LInkx Tracks Devices

Devices change IPs. Android randomizes MACs. LInkx handles all of it.

**3-phase device re-identification:**

```
Phase 1: Direct TCP probe to last known IP          (~50ms, instant)
Phase 2: ARP table MAC lookup                       (skipped for Android/Windows)
Phase 3: Named key scan — the KEY is the identity
          LInkx tries device's key against every SSH device on subnet.
          First device that accepts it = the device. IP irrelevant.
```

Once you name your devices (`V-15_to_Vivo`), that key is the permanent identity. Factory reset the phone, reinstall, change network — LInkx still finds it.

---

## Transfer Logic Reference

| Situation | What LInkx does |
|---|---|
| Single file, new at destination | Direct scp |
| Single file, exists at destination | rsync (delta) or overwrite / Copy folder |
| Single file, any size | Never tarred |
| Multiple files ≤ threshold | Direct scp each |
| Multiple files > threshold | Bundle → Transfer.tar → scp → extract |
| Folder | Tar if file count > threshold |
| Compressed item (.7z) | Always counts as 1 file for threshold |
| rsync missing | Offer install, or fallback to scp |
| Windows remote | scp always (rsync to Windows unreliable) |

**Default tar threshold: 10 files.** Change anytime via `[X]` in Transfer menu.

---

## Data Files

LInkx stores everything alongside `linkx.py`:

```
Linkx
|-linkx.py                 ← the entire application
|-README.md
|-LICENSE
|-.linkx_hosts.json        ← known devices, IPs, MACs, OS info
|-.linkx_keys.json         ← device ID → SSH key file mapping
|-.linkx_vault.json        ← vault device list
|-.linkx_quick.json        ← Quick Share queues and last-used paths
|-linkx_trusted.json      ← trusted device list (auto-transfer)

```

SSH keys live in `~/.ssh/` named `ThisDevice_to_OtherDevice` (e.g. `V-15_to_Vivo`).

---

## Configuration

Edit these constants near the top of `linkx.py`:

| Constant | Default | What it controls |
|---|---|---|
| `W` | `64` | Menu width. 50=phone, 64=laptop, 80=wide monitor |
| `TAR_THRESHOLD` | `10` | File count above which items are tar-bundled |
| `SCAN_TIMEOUT` | `1.2` | Seconds per host during scan |
| `QS_POLL_INTERVAL` | `8` | Quick Share watcher interval (seconds) |
| `SHOW_PASSWORD` | `False` | Debug: show SSH verbose output during setup |

---

## Version

```bash
python3 linkx.py --version
# LInkx v1.0.0.0
# Author  : Kiran Pradeep Malik
# Email   : sysarch.kiran@gmail.com
# Launched: 2026-04-28
```

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

**Kiran Pradeep Malik**
📧 sysarch.kiran@gmail.com
📸 [@kiran_0807x](https://www.instagram.com/kiran_0807x?igsh=MWZtaTcyMGg5ODkzbw==)
🐙 [Arch-Kiran](https://github.com/Arch-Kiran)

---
