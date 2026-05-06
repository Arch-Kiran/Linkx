# LInkx

> Transfer files between any devices on your network at full native speed — no cloud, no accounts, no bullshit.

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
  ●  Kali              192.168.45.150   kira        Kali Linux  🔑 V-15_to_Kali  🔒
  ────────────────────────────────────────────────────────────────
    [Q]  Quick Share  ⚡  pick files → auto-send / queue when offline
    [V]  Vault  🔒  instant access to paired Linkx folders
  ────────────────────────────────────────────────────────────────
    [1]  Scan network          find SSH devices
    [2]  Transfer files        send / receive
    [3]  Setup device          first-time connect (one-way)
    [P]  Pair devices  🔗     two-way key exchange (both run LInkx)
    [4]  My SSH keys
    [5]  Remove device
    [6]  Rename / nickname a device
    [7]  SSH Server    start / stop this device's server
    [8]  Install tools  7-Zip / rsync / ssh    ✓ all ready
    [T]  Raw terminal  run commands without quitting
    [?]  How to use this tool
    [0]  Exit
  ────────────────────────────────────────────────────────────────
  ❯  Choose:
```

---

### Step 1 — Start SSH on the Target Device

Before LInkx can reach another device, that device needs its SSH server running.  
Use `[7] SSH Server` to start/stop SSH on **your** device.

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

**Linux (Debian / Ubuntu / Kali):**
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

  Scan strategy:
    Phase 1 → Stored devices (last known IP + MAC)  [instant]
    Phase 2 → Full subnet scan  192.168.100.x, 192.168.45.x, 10.100.83.x

    Ports : 22 (Linux/Win/Mac)  8022 (Android/Termux)
    Speed : 1.2s/host  |  200 threads  |  ports 22+8022 parallel
  ────────────────────────────────────────────────────────────────
  FOUND [1]  192.168.45.162    :8022  MAC:be:5f:d9:1f:6d:6b  Android
         → type 1 + Enter to jump there now
  ❯  Device number (or Enter when done):
```

**How the scanner works:**
- Phase 1 probes all known devices simultaneously using their last known IP (~0.5s)
- Phase 2 blasts the full subnet with OS-aware thread count (100–300 threads)
- Both port 22 and 8022 probed in parallel per IP — worst case 1.2s per host
- Banner grab identifies OS from SSH handshake with no auth needed
- VMware bridged VMs: scans both the VM subnet and hotspot subnets via gateway detection
- Devices with changed IPs are re-identified by their stored SSH key fingerprint

---

### Step 3 — First-Time Connect: Setup `[3]` or Pair `[P]`

#### Option A — Setup `[3]`
One-way setup. You know the other device's password. LInkx installs a key on the remote so you never need the password again. The remote device does not need LInkx installed.

```
  What OS is on 192.168.45.162?
  [1]  Android / Termux              port 8022  ← detected
  [2]  Linux — Debian/Ubuntu/Mint    port 22
  [w]  Windows 10/11 (OpenSSH)       port 22
  ...

  Remote username [u0_a226]:

  SSH will ask for the password of u0_a226@192.168.45.162
  Type it when prompted (characters are hidden).

  ✓  Key login confirmed — u0_a226@192.168.45.162
  ✓  Passwordless connection established!
```

After setup, name both devices:
```
  Your device name [V-15]: V-15
  Other device name [u0_a226]: Vivo

  Renaming key:  V-15_to_Vivo
  ✓  Key renamed: V-15_to_Vivo
  ✓  Identity: Vivo remembered by key — survives IP/MAC changes
```

The key file `V-15_to_Vivo` is permanent. If the phone changes IP or MAC, LInkx finds it by trying this key against every device on the subnet — the first one that accepts it is Vivo.

---

#### Option B — Pair `[P]` (both devices run LInkx — two-way)

Pairing is a **two-way simultaneous setup**. Both devices run LInkx. After pairing, both devices can SSH into each other freely — no passwords, no manual config, forever.

**What makes Pair different from Setup:**
- Setup installs a key in one direction only (you → them)
- Pairing installs keys in both directions simultaneously (you → them AND them → you)
- Both devices appear in each other's known device list immediately
- Both devices can initiate transfers to each other at any time

**Before choosing HOST or CLIENT, LInkx starts the SSH server on your device automatically.** This is required so the other device can reach you after pairing.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                ZERO-CONFIG PAIRING                             ║
  ║          Pair two devices running linkx.py                     ║
  ╚════════════════════════════════════════════════════════════════╝

  Both devices run linkx.py and choose Pair.
  Both devices start SSH server first.
  HOST opens a pairing listener, CLIENT scans and finds it,
  confirms a PIN, both enter each other's password once,
  keys installed both ways — no passwords ever again.

  Starting SSH server on this device...
  ✓  SSH server ready on port 22

  [1]  HOST   — I am the device others connect TO
  [2]  CLIENT — I will find and connect to the HOST

  ❯  Choose:
```

If SSH server cannot start, LInkx warns you and asks if you want to continue one-way:
```
  ⚠  SSH server could not start on this device.
     The other device will NOT be able to connect to you.
     You can still connect TO the other device (one-way).

  Continue anyway? [N]:
```

---

**The full pairing flow — step by step:**

**Phase 0 — SSH server starts on both devices**  
Both devices call `[7]`-equivalent automatically. SSH is running on both before any role is chosen.

**Phase 1 — PIN coordination**  
HOST generates a 6-digit PIN and opens a TCP listener on port 55222. CLIENT scans the LAN with up to 300 parallel probes, finds HOST in seconds. No IP entry needed. The PIN is shown on both screens — you confirm it matches visually before anything is exchanged.

```
  HOST screen:                        CLIENT screen:
  ╔════════════════════╗              ╔════════════════════╗
  ║   482917           ║              ║   482917           ║
  ╚════════════════════╝              ╚════════════════════╝

  CLIENT is scanning the LAN...       PIN confirmed? [Y]:
```

**Phase 2 — Mutual key install (one password each, once)**  
This is the core. Two password SSH sessions happen — one from each side.

- **CLIENT → HOST**: CLIENT enters HOST's password. LInkx installs CLIENT's fresh key on HOST's `authorized_keys`. CLIENT can now SSH to HOST without a password forever.
- **HOST → CLIENT**: HOST enters CLIENT's password. LInkx installs HOST's fresh key on CLIENT's `authorized_keys`. HOST can now SSH to CLIENT without a password forever.

Each password is entered exactly once, on its own screen. LInkx never stores or sees any password. The OS handles it directly.

```
  CLIENT side:                         HOST side:
  Step 1/2: Installing our key on      Two-way setup: Installing HOST
  HOST                                 key on CLIENT
  Enter password of kali@192.168.1.10  Enter password of user@192.168.1.20
  [password typed — hidden]            [password typed — hidden]
  ✓  Our key installed on HOST ✓       ✓  HOST key installed on CLIENT ✓
```

**Phase 3 — Both devices saved to each other's database**  
After both sessions complete, both devices call `save_hosts()`. The device appears in Transfer, Quick Share, Vault, and the main device list on both sides immediately. `key_ok: True` is set on both records.

**Phase 4 — Naming ceremony**  
Both devices run the naming ceremony independently. Keys are renamed from their temporary device-ID labels to friendly names.

```
  Your device name [kalibox]: Kali
  Other device name [DESKTOP-V15]: V-15

  Renaming key:  Kali_to_V-15
  ✓  Key renamed: Kali_to_V-15
  ✓  Identity: V-15 remembered by key — survives IP/MAC changes
```

**Result:**
```
  TWO-WAY PAIRING COMPLETE!
  ✓  We can SSH/SCP to HOST (kali@192.168.1.10)
  ✓  HOST can SSH/SCP to us (key installed both ways)
     No password ever needed again.
```

**Edge cases handled automatically:**
- If SSH server fails to start on one side — warns and offers one-way continuation
- If HOST times out before CLIENT connects — clear timeout message, no hang
- After CLIENT first contacts HOST, HOST gives 120 more seconds for the password entry step before timing out — no rush
- If one password entry fails — that direction is one-way; the other direction still works
- VMware bridged VMs: CLIENT scans both the VM subnet and phone hotspot subnets via gateway detection, finding HOST even across different subnets
- Android/Termux: `os.path.realpath` resolves symlink paths before key rename — no `FileNotFoundError`
- Windows HOST: `sshd_config` is automatically fixed to enable `PubkeyAuthentication yes` and ACLs on `administrators_authorized_keys` are corrected so the key actually works

---

### Step 4 — Transfer Files `[2]`

```
  ╔════════════════════════════════════════════════════════════════╗
  ║             TRANSFER  u0_a226@10.100.83.199:8022               ║
  ║                      Android / Termux  Vivo                    ║
  ╚════════════════════════════════════════════════════════════════╝
    Key  : V-15_to_Vivo
    MAC  : 12:5f:43:0e:dd:04   ID: 43af72be

  [1]  Send     →  file or folder TO this device
  [2]  Receive  ←  file or folder FROM this device
  [3]  Browse remote files
  [4]  Run command on remote
  [5]  Open SSH shell  (full terminal on REMOTE)
  [S]  Share Linkx  →  send this app to device
  [T]  Raw local terminal
  [X]  Tar threshold : 10 files
  ────────────────────────────────────────────────────────────────
  [6]  Re-setup  (change user / reinstall key)
  [V]  🔒 In Vault  (already added)
  [0]  Back
  ❯  Choose:
```

#### Send `[1]`

Pick files one by one, optionally compress each with 7-Zip, then pick the remote destination by live-browsing the remote filesystem. LInkx checks if items already exist and offers rsync (delta), overwrite, or copy to new folder. If total file count exceeds the tar threshold, items are bundled into `Transfer.tar` first for speed.

```
  Total files: 48  (threshold: 10)
  ✓  Transfer.tar ready  (18.4MB)

  → Transfer.tar
  Transferring: Transfer.tar
  [»»»»»»»»»»»»»»»»»»»»»»»»»»»»]  100%  4.2MB/s  ETA 0:00
  ✓  Transferred!
  ✓  Transfer.tar extracted and deleted on remote ✓
```

#### Tar Threshold `[X]`

Control when files get bundled. Default is 10. Single files are never tarred regardless of size.

```
  0  = always tar (except single files)
  10 = tar only when count > 10  (default)
  99 = almost never tar
```

---

### Step 5 — Vault `[V]`

Vault is a curated list of devices you transfer with regularly. Each Vault device gets a shared `Linkx/` folder in Downloads on both devices. One keypress to browse, send, or receive from that shared folder.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                     VAULT  —  Vivo                             ║
  ╚════════════════════════════════════════════════════════════════╝

  ● Connected  u0_a226@10.100.83.199

  Local  Linkx:   /home/kira/Downloads/Linkx
  Remote Linkx:   /sdcard/Download/Linkx

  [1]  Browse remote Linkx folder
  [2]  Send   → TO device
  [3]  Receive ← FROM device
  [0]  Back
```

---

### Step 6 — Quick Share `[Q]`

Pick files first. If the device is online, transfer fires immediately. If offline, the transfer is queued and fires automatically the moment the device comes online.

```
  [ 1]  ●  Vivo     Android / Termux    ★
  [ 2]  ○  Kali     Linux        [queued]
```

**Trusted devices** (`★`) — transfer fires silently without any confirmation prompt.

**Queued transfer notification:**
```
  ● Kali found at 192.168.45.150
  Queued: send 2 item(s) → /home/kira/Downloads

  [Y]  Transfer now
  [P]  Pause — ask again in 2 minutes
  [N]  Cancel and clear queue
```

---

### Step 7 — Install Tools `[8]`

```
  7-Zip : ✓  installed
  rsync : ✗  optional — scp fallback active
  ssh   : ✓  installed
  tar   : ✓  installed
```

**7-Zip** — compress before sending. Installed via `apt` / `dnf` / `pacman` / `brew` / `winget`.  
**rsync** — delta transfers. Only sends changed bytes. Linux ↔ Linux / Android / macOS. Windows uses scp fallback.

---

### SSH Server Manager `[7]`

Start or stop the SSH server on this device with one keypress. LInkx detects your OS and runs the correct command. On Windows it also manages firewall rules automatically.

```
  Status : ● RUNNING  (port 22)

  [1]  Stop SSH server
  [2]  Show start commands  (for all OS)
  [3]  Show stop  commands  (for all OS)
  [0]  Back
```

---

### Share LInkx `[S]`

Send `linkx.py` itself to another device. Creates `Downloads/Linkx/Linkx app/linkx.py` on the remote and shows the exact command to run it.

---

## Device Identity — How LInkx Tracks Devices

Devices change IPs. Android randomizes MACs. LInkx handles all of it.

**3-phase device re-identification:**
```
Phase 1: Direct TCP probe to last known IP         (~50ms, instant)
Phase 2: ARP table MAC lookup                      (skipped for Android/Windows)
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
| Compressed item (.7z) | Always counts as 1 file |
| rsync missing | Offer install, or fallback to scp |
| Windows remote | scp always (rsync to Windows unreliable) |

**Default tar threshold: 10 files.**

---

## Setup vs Pair — Which to Use

| | Setup `[3]` | Pair `[P]` |
|---|---|---|
| Both devices need LInkx | ❌ No | ✅ Yes |
| Password required | Once (yours → theirs) | Once each side |
| Keys installed | One direction only | Both directions |
| Other device appears in your list | ✅ | ✅ |
| You appear in other device's list | ❌ | ✅ |
| Other device can initiate transfer to you | ❌ | ✅ |
| Best for | Remote servers, one-time setup | Daily use between personal devices |

---

## Data Files

LInkx stores everything alongside `linkx.py`:

```
Linkx/
├── linkx.py                ← the entire application
├── README.md
├── LICENSE
├── .linkx_hosts.json       ← known devices, IPs, MACs, OS info
├── .linkx_keys.json        ← device ID → SSH key file mapping
├── .linkx_vault.json       ← vault device list
├── .linkx_quick.json       ← Quick Share queues and last-used paths
└── .linkx_trusted.json     ← trusted device list (auto-transfer)
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
