<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=32&duration=2800&pause=1200&color=00D9FF&center=true&vCenter=true&width=800&lines=Linkx;Your+files.+Your+network.;No+cloud.+No+accounts.+Full+speed." alt="Linkx" />

<br/>

**The file transfer tool that respects you.**
One Python file. Zero dependencies. Hardware-maximum speed. No cloud. No accounts. No bullshit.

<br/>

[![Python](https://img.shields.io/badge/Python-3.8%2B-58a6ff?style=flat-square&logo=python&logoColor=white&labelColor=21262d)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-3fb950?style=flat-square&labelColor=21262d)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android%20%7C%20Windows%20%7C%20macOS-bc8cff?style=flat-square&labelColor=21262d)](https://github.com/Arch-Kiran/Linkx)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-f85149?style=flat-square&labelColor=21262d)](https://github.com/Arch-Kiran/Linkx)
[![SSH](https://img.shields.io/badge/Transport-SSH%20%2F%20SCP-d29922?style=flat-square&labelColor=21262d)](https://github.com/Arch-Kiran/Linkx)

<br/>

```bash
# get it
git clone https://github.com/Arch-Kiran/Linkx.git && cd Linkx

# run it
python3 linkx.py
```

No installer. No pip. No setup.py. Clone and run — that is it.  
→ [Full installation guide for all platforms](#installation)

<br/>

</div>

---

<div align="center">

### While you were reading this, someone's cloud upload was still at 3%.

</div>

---

## The Problem With Every Other Tool

| Tool | What it costs you |
|---|---|
| AirDrop | Apple devices only. Excluded by design. |
| Bluetooth | Real. Actual. Pain. |
| WhatsApp / Telegram | 16 MB limit. Compression destroys your photos. Someone else's server. |
| Google Drive / iCloud | Upload to their server. Download from their server. Pray for bandwidth. |
| USB cable | Find the cable. Find the right cable. Find the adapter for the cable. |
| Other LAN tools | Installation. Config files. Port forwarding. Why. |

**Linkx:** open terminal, run one file, transfer at the speed your hardware allows. Done.

---

## What Linkx Actually Is

A single Python file that builds the right `scp` command for your exact situation and fires it.

Python touches zero bytes of your data. The OS handles the transfer natively at full hardware speed. No buffering. No re-encoding. No overhead. The progress bar you see is the actual `scp` process running — not a wrapper, not a simulation.

```
Your device  ──── SSH / SCP ────▶  Their device
              direct, encrypted
              nothing in between
```

---

## Real Numbers From Real Hardware

Three devices. One hotspot. Real conditions — not a benchmark.

**The setup:** HP Victus (WiFi 6) + Vivo Y33s (WiFi 5) + Redmi 4A. The Vivo acts as 5GHz hotspot for both. No router. Devices talking directly through the phone.

```
Laptop → Vivo Y33s · 5GHz hotspot · no interference nearby
█████████████  39 MB/s

Laptop → Kali VM · VMware Host-Only · zero middleman at all
████████████████████████████████████████████████  130 MB/s

Same devices · same room · Airtel router ON nearby (not even connected to it)
███  6 MB/s
```

The router was not part of the connection. It was just **on**, in the same room, competing for the 5GHz band. Drove home, ran the same transfer again — **39 MB/s**. Hypothesis confirmed.

That is not a Linkx number. That is physics. Linkx gets out of the way and lets your hardware run.

**What steals your speed:** nearby routers eating airtime, Bluetooth and mobile data splitting the chip's attention, any middleman adding hops.
**What gets it back:** kill Bluetooth, turn off mobile data, move away from other routers, use a direct hotspot.

---

## How It Looks — Full Walkthrough

Every screen shown exactly as it appears in the terminal.

---

### The Home Screen

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                LINKX  —  Network File Transfer                 ║
  ║                      V-15   192.168.100.1                      ║
  ╚════════════════════════════════════════════════════════════════╝
    Known devices: 5   Key ready: 2   Vault: 1
    ⚡ 1 transfer(s) queued — pinging offline device(s)...
  ────────────────────────────────────────────────────────────────
  ●  Vivo    10.100.83.199    u0_a226    Android / Termux  🔑 V-15_to_Vivo  ★
  ●  Kali    192.168.45.150   kira       Linux             🔑 V-15_to_Kali  🔒
  ────────────────────────────────────────────────────────────────
    [Q]  Quick Share  ⚡  pick files → auto-send / queue when offline
    [V]  Vault  🔒  instant access to paired Linkx folders
  ────────────────────────────────────────────────────────────────
    [1]  Scan network           find SSH devices
    [2]  Transfer files          send / receive
    [3]  Setup device            first-time connect (one-way)
    [P]  Pair devices  🔗       two-way key exchange
    [4]  My SSH keys
    [5]  Remove device
    [6]  Rename / nickname a device
    [7]  SSH Server    start / stop this device's server
    [8]  Install tools
    [T]  Raw terminal
    [?]  How to use this tool
    [0]  Exit
  ────────────────────────────────────────────────────────────────
  ❯  Choose:
```

`●` = online  `○` = offline  `🔑` = key ready  `🔒` = in Vault  `★` = trusted (silent auto-transfer)

---

### Scanning the Network `[1]`

No IP entry. No config. Linkx finds every SSH device on your network automatically.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                        SCANNING NETWORK                        ║
  ╚════════════════════════════════════════════════════════════════╝

  Scan strategy:
    Phase 1 → Stored devices (last known IP + MAC)  [instant]
    Phase 2 → Full subnet scan  192.168.100.x, 192.168.45.x, 10.100.83.x
    5 stored device(s) — probed first

    Ports : 22 (Linux/Win/Mac)  8022 (Android/Termux)
    Speed : 1.2s/host  |  200 threads  |  ports 22+8022 parallel
  ────────────────────────────────────────────────────────────────
  FOUND [1]  192.168.45.162    :8022  MAC:be:5f:d9:1f:6d:6b  Android
         → type 1 + Enter to jump there now
  ❯  Device number (or Enter when done):
```

**How it works under the hood:**
- Phase 1 probes all known devices simultaneously using their last known IP — instant if nothing changed
- Phase 2 blasts the full subnet with 100–300 parallel threads depending on OS
- Both port 22 and 8022 probed in parallel per IP — worst case 1.2s per host, not 2.4s
- SSH banner identifies OS without any authentication
- VMware bridged VMs: scans both the VM subnet and hotspot subnets via gateway detection
- Devices with changed IPs re-identified by their stored SSH key fingerprint

---

### First-Time Connect — Setup `[3]`

One-way. Remote device does not need Linkx. Enter their password once. Never again.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                  SETUP — 192.168.45.162                        ║
  ╚════════════════════════════════════════════════════════════════╝

  Detecting remote OS from SSH banner...
  Detected: android

  What OS is on 192.168.45.162?
  [1]  Android / Termux              port 8022  ← detected
  [2]  Linux — Debian/Ubuntu/Kali    port 22
  [w]  Windows 10/11 (OpenSSH)       port 22
  ...
  ❯  OS type [1]:

  Remote username (run 'whoami' in Termux → e.g. u0_a226)
  ❯  Username []:

  SSH will ask for the password of u0_a226@192.168.45.162
  Type it when prompted. Characters are hidden.

  [password entered once — key installed automatically]

  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Key login confirmed — u0_a226@192.168.45.162             │
  └──────────────────────────────────────────────────────────────┘
  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Passwordless connection established!                      │
  └──────────────────────────────────────────────────────────────┘
```

Then name both devices — this name survives everything:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                    NAME THIS CONNECTION                        ║
  ╚════════════════════════════════════════════════════════════════╝

  ❯  Your device name [V-15]:   V-15
  ❯  Other device name [u0_a226]: Vivo

  Renaming key:  V-15_to_Vivo
  ✓  Key renamed: V-15_to_Vivo
  ✓  Identity: Vivo remembered by key — survives IP/MAC changes
```

`V-15_to_Vivo` is now the permanent identity of this connection. Factory reset the phone, change network, get a new IP — Linkx tries this key against every device on the subnet. First one that accepts it is Vivo.

---

### First-Time Connect — Pair `[P]`

Two-way. Both devices run Linkx. SSH server starts automatically on both. Keys installed in both directions. One password each side. Never again.

**HOST side** shows a PIN and waits:
```
  ╔════════════════════════════════════════════════════════════════╗
  ║             PAIRING — HOST MODE                                ║
  ╚════════════════════════════════════════════════════════════════╝

  ✓  SSH server ready on port 22

    PIN — CLIENT must confirm this matches:

  ╔════════════════════╗
  ║   482917           ║
  ╚════════════════════╝

  CLIENT is scanning the LAN to find us...
```

**CLIENT side** scans, finds HOST, confirms PIN:
```
  ╔════════════════════════════════════════════════════════════════╗
  ║             PAIRING — CLIENT MODE   HOST found: V-15           ║
  ╚════════════════════════════════════════════════════════════════╝

  HOST device:
    IP       : 192.168.100.1
    Hostname : V-15
    SSH port : 22

  Confirm PIN matches HOST screen:

  ╔════════════════════╗
  ║   482917           ║
  ╚════════════════════╝

  [Y]  PIN matches — pair now
  [N]  Wrong device — cancel
  ❯  PIN confirmed? [Y]:

  Step 1/2: Installing our key on HOST
  Enter password of user@192.168.100.1
  [password entered — key installed on HOST]
  ✓  Our key installed on HOST ✓

  Step 2/2: Installing HOST key locally
  ✓  HOST key installed locally ✓

  ┌──────────────────────────────────────────────────────────────┐
  │  TWO-WAY PAIRING COMPLETE!                                   │
  │  ✓  We can SSH/SCP to HOST                                   │
  │  ✓  HOST can SSH/SCP to us                                   │
  │     No password ever needed again.                           │
  └──────────────────────────────────────────────────────────────┘
```

Result: both devices appear in each other's device list. Either can initiate transfers. No passwords. Forever.

---

### Transfer Menu `[2]`

```
  ╔════════════════════════════════════════════════════════════════╗
  ║             TRANSFER  u0_a226@10.100.83.199:8022               ║
  ║                      Android / Termux  Vivo                    ║
  ╚════════════════════════════════════════════════════════════════╝
    Key  : V-15_to_Vivo
    MAC  : 12:5f:43:0e:dd:04   ID: 43af72be

  ────────────────────────────────────────────────────────────────
    [1]  Send     →  file or folder TO this device
    [2]  Receive  ←  file or folder FROM this device
    [3]  Browse remote files
    [4]  Run command on remote
    [5]  Open SSH shell  (full terminal on remote device)
    [S]  Share Linkx  →  send this app to device
    [T]  Raw local terminal
    [X]  Tar threshold : 10 files
  ────────────────────────────────────────────────────────────────
    [6]  Re-setup  (change user / reinstall key)
    [V]  🔒 In Vault  (already added)
    [0]  Back
  ❯  Choose:
```

#### Sending Files

Pick items. Optionally compress each with 7-Zip. Then browse the remote to pick destination:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║              SEND — Queue    2 item(s) selected                ║
  ╚════════════════════════════════════════════════════════════════╝

  [ 1]  /home/kira/Books  (folder — 47 files)  → Books.7z  [.7z]
  [ 2]  /home/kira/notes.pdf  (1.2MB)

  [A]  Add another item
  [D]  Done — proceed to send
```

Live-browse the remote filesystem to pick where files land:

```
    Locations on  u0_a226@10.100.83.199  [Android / Termux]:

  [ 1]  Termux Home (~)              /data/data/com.termux/files/home
  [ 2]  Downloads  (symlink)         ~/storage/downloads
  [ 3]  Internal Storage (symlink)   ~/storage/shared
  [ 4]  DCIM / Camera                ~/storage/dcim
  ...
    [P]  Paste path directly
```

If file count exceeds the tar threshold, items are bundled automatically:

```
  Total files: 48  (threshold: 10)
  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Transfer.tar ready  (18.4MB)                             │
  └──────────────────────────────────────────────────────────────┘

  → Transfer.tar
  [»»»»»»»»»»»»»»»»»»»»»»»»»»»»]  100%  36.2MB/s  ETA 0:00

  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Transferred!                                             │
  └──────────────────────────────────────────────────────────────┘
  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Transfer.tar extracted and deleted on remote ✓           │
  └──────────────────────────────────────────────────────────────┘
```

#### Conflict Handling

File already exists at destination? Choose what happens:

```
  These items already exist at destination:
    Books.7z

  [1]  Install rsync then use delta transfer (only changed bytes)
  [2]  Overwrite existing files
  [3]  Send to Copy subfolder instead
  [0]  Cancel
```

#### Transfer Logic Reference

| Situation | What Linkx does |
|---|---|
| Single file, new at destination | Direct scp |
| Single file, already exists | rsync delta, overwrite, or copy folder |
| Single file, any size | Never tarred |
| Multiple files under threshold | Direct scp each |
| Multiple files over threshold | Bundle into Transfer.tar → scp → extract |
| Folder | Tar if file count exceeds threshold |
| Compressed item | Always counts as 1 file regardless of contents |
| rsync missing | Offer to install, or fallback to scp |
| Windows remote | scp always — rsync to Windows is unreliable |

**Default tar threshold: 10 files.** Change anytime with `[X]` in the Transfer menu.

---

### Vault `[V]`

A curated list of devices you use regularly. Each Vault device gets a shared `Linkx/` folder in Downloads on both sides. One keypress to browse, send, or receive from that shared space.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                      LINKX VAULT                               ║
  ║                  Your trusted device library                   ║
  ╚════════════════════════════════════════════════════════════════╝

  [ 1]  ●  Vivo     Android / Termux
  [ 2]  ○  Kali     Linux

  ● = online now  ○ = offline
  ❯  Choose device:
```

Inside a Vault device:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                     VAULT  —  Vivo                             ║
  ╚════════════════════════════════════════════════════════════════╝

  ● Connected  u0_a226@10.100.83.199

  Local  Linkx:   /home/kira/Downloads/Linkx
  Remote Linkx:   /sdcard/Download/Linkx

  [1]  Browse remote Linkx folder
  [2]  Send   → file/folder TO device
  [3]  Receive ← file/folder FROM device
  [0]  Back
```

---

### Quick Share `[Q]`

Pick files. Pick device. Done. Online = transfers immediately. Offline = queues automatically.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                  QUICK SHARE  ⚡                               ║
  ║       Instant transfer — queue when offline                    ║
  ╚════════════════════════════════════════════════════════════════╝

  [ 1]  ●  Vivo     Android / Termux    ★
  [ 2]  ○  Kali     Linux        [queued]

  ● = online  ○ = offline  ★ = trusted (fires silently)
```

**Offline device** — choose how to handle it:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                   DEVICE OFFLINE — Kali                        ║
  ╚════════════════════════════════════════════════════════════════╝

  [1]  SSH running — scan and update IP, then transfer
  [2]  SSH not running — queue for when it comes online
  [0]  Back
```

**When the device comes back online** — fires automatically:

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                    DEVICE ONLINE! — Kali                       ║
  ╚════════════════════════════════════════════════════════════════╝

  ● Kali found at 192.168.45.150

  Queued: send 2 item(s) → /home/kira/Downloads
    Books.7z   (18.4MB)
    notes.pdf  (1.2MB)

  [Y]  Transfer now
  [P]  Pause — ask again in 2 minutes
  [N]  Cancel and clear queue
  ❯  Choose [Y]:
```

For **trusted devices** `★`, the entire confirmation is skipped. Transfer fires silently the moment they appear online. No prompt. No waiting.

---

### Device Identity — How Linkx Tracks Devices Across IP Changes

Devices change IPs. Android randomises MACs on every connection. Linkx handles all of it automatically, silently, in the background.

```
Phase 1 — Last known IP
  Direct TCP probe, ~50ms.
  Works if IP has not changed — instant.

Phase 2 — ARP / MAC lookup
  Find current IP from MAC address in ARP table.
  Works if device got a new DHCP address but is still on the same network.
  Skipped for Android, Windows, macOS — these randomise MACs per connection.

Phase 3 — Named key scan
  Try the device's named SSH key (V-15_to_Vivo) against every SSH host
  found on the subnet. First device that accepts it = found.
  Works even after factory reset on a completely new network.
```

Once named, `V-15_to_Vivo` is the permanent identity of that connection. Not the IP. Not the MAC. The key.

---

### SSH Server Manager `[7]`

Start or stop SSH on this device from inside Linkx. Handles `systemctl`, `launchctl`, `net start`, and Termux `sshd` automatically. On Windows also manages firewall rules.

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
```

---

### Install Tools `[8]`

Linkx detects what is installed and offers to install anything missing using the correct package manager for your OS.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                       INSTALL TOOLS                            ║
  ╚════════════════════════════════════════════════════════════════╝

  7-Zip : ✓  installed
  rsync : ✗  optional — scp fallback active
  ssh   : ✓  installed
  tar   : ✓  installed

  [1]  Install / upgrade  7-Zip
  [2]  Install / upgrade  rsync
  [3]  Install / upgrade  openssh
  [0]  Back
```

**7-Zip** — compress before sending. Installed via `apt` / `dnf` / `pacman` / `brew` / `winget`.
**rsync** — delta transfers. Only sends changed bytes. Linux, Android, macOS. Windows uses scp fallback.

---

### Share Linkx `[S]`

Send `linkx.py` itself to any paired device. Creates `Downloads/Linkx/Linkx app/linkx.py` on the remote and shows the exact command to run it.

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                       SHARE LINKX                              ║
  ╚════════════════════════════════════════════════════════════════╝

  This script:  /home/kira/tools/linkx.py  (490KB)
  Destination:  u0_a226@10.100.83.199:~/storage/downloads/Linkx/Linkx app

  [Y]  Send now
  [0]  Cancel

  ┌──────────────────────────────────────────────────────────────┐
  │  ✓  Linkx sent to u0_a226@10.100.83.199 ✓                   │
  └──────────────────────────────────────────────────────────────┘

  To run on the remote device:
    cd ~/storage/downloads/Linkx/Linkx\ app
    python linkx.py
```

---

## Features

<details>
<summary><b>Transfer</b> — send anything, any size, any direction</summary>
<br/>

- Send and receive files and folders in both directions with a live remote file browser
- Smart tar bundling — hundreds of files become one stream, extracted on arrival. Threshold you control.
- Delta transfer via rsync — only changed bytes sent when file already exists at destination
- 7-Zip compression — compress before sending, up to 6 levels, optional per file
- Conflict resolution — file exists? Choose delta, overwrite, or copy to new folder.

</details>

<details>
<summary><b>Connection</b> — set up once, connect forever</summary>
<br/>

- Pair `[P]` — both devices run Linkx, LAN scan finds each other in seconds, PIN confirms identity, one password each side, keys in both directions. No passwords ever again.
- Setup `[3]` — remote device does not need Linkx. One password. One direction. Done.
- Permanent identity — key named `V-15_to_Vivo` survives IP changes, MAC randomisation, network changes, factory resets.
- 3-phase tracking — last IP, then ARP/MAC, then full subnet key scan. Found even after factory reset.

</details>

<details>
<summary><b>Automation</b> — fire and forget</summary>
<br/>

- Quick Share `[Q]` — pick files, pick device, done. Offline? Queued. Fires the instant they return.
- Trusted devices — marked with star. Transfers fire silently. No prompt. No waiting.
- Background watcher — polls every 8 seconds. You do not have to think about it.

</details>

<details>
<summary><b>Organisation</b> — built for daily use</summary>
<br/>

- Vault `[V]` — shared `Linkx/` folder in Downloads on both sides. One keypress to browse, send, receive.
- Named keys — `V-15_to_Vivo` not `192.168.1.42`. The name survives everything.
- Nicknames — short display names in all menus.

</details>

<details>
<summary><b>Control</b> — everything from one terminal</summary>
<br/>

- SSH shell `[5]` — full terminal on any paired device without leaving Linkx
- Remote commands `[4]` — one-off commands, output shown inline
- SSH server manager `[7]` — start/stop SSH on this device. Handles systemctl, launchctl, net start, Termux sshd.
- Tool installer `[8]` — installs openssh, rsync, tar, 7-Zip via the right package manager for your OS
- Share Linkx `[S]` — send `linkx.py` itself to any connected device

</details>

---

## Platform Support

| Platform | Works | Port | Notes |
|---|---|---|---|
| Linux all distros | Full | 22 | |
| Android / Termux | Full | 8022 | |
| macOS | Full | 22 | |
| Windows 10 / 11 | Full | 22 | OpenSSH built-in since 1809 |
| Windows 7 / 8 | Partial | 22 | Manual Win32-OpenSSH install |
| iOS | No | — | No SSH server without jailbreak |

---

## Installation

**Step 1 — Get the file**

```bash
git clone https://github.com/Arch-Kiran/Linkx.git && cd Linkx
```

Or download `linkx.py` directly. That is the entire app.

**Step 2 — Python 3.8+**

Already on Linux and macOS. On Windows: [python.org](https://python.org) — tick "Add to PATH".
On Termux: `pkg install python`

**Step 3 — SSH server on the target device**

<details>
<summary>Android / Termux</summary>

```bash
pkg install openssh && passwd && sshd
```
</details>

<details>
<summary>Linux — Debian / Ubuntu / Kali</summary>

```bash
sudo apt install openssh-server && sudo systemctl start ssh
```
</details>

<details>
<summary>Linux — Fedora / RHEL</summary>

```bash
sudo dnf install openssh-server && sudo systemctl start sshd
```
</details>

<details>
<summary>Linux — Arch</summary>

```bash
sudo pacman -S openssh && sudo systemctl start sshd
```
</details>

<details>
<summary>Windows 10 / 11</summary>

```
Settings → Apps → Optional Features → OpenSSH Server → Install
```
Then press `[7]` inside Linkx — handles service start and firewall rules automatically.
</details>

<details>
<summary>macOS</summary>

```
System Settings → General → Sharing → Remote Login → ON
```
</details>

**Step 4 — Run**

```bash
python3 linkx.py     # Linux / macOS / Termux
python linkx.py      # Windows
```

First run opens the guide automatically.

---

## Configuration

Top of `linkx.py`:

| Constant | Default | What it does |
|---|---|---|
| `W` | `64` | Menu width. 50 for phones, 80 for wide terminals. |
| `TAR_THRESHOLD` | `10` | Bundle into tar above this file count |
| `SCAN_TIMEOUT` | `1.2` | Seconds per host during scan |
| `QS_POLL_INTERVAL` | `8` | Quick Share polling interval in seconds |
| `SHOW_PASSWORD` | `False` | Debug: verbose SSH output during setup |

---

## Data Files

Everything alongside `linkx.py`. Nothing hidden in system directories.

```
.linkx_hosts.json     known devices
.linkx_keys.json      device ID to key file
.linkx_vault.json     vault list
.linkx_quick.json     Quick Share queues
.linkx_trusted.json   trusted devices
```

SSH keys in `~/.ssh/` named `ThisDevice_to_OtherDevice`.

---

## License

MIT. Use it. Modify it. Ship it. No strings.

---

<div align="center">

**Kiran Pradeep Malik**

[📧 Email](mailto:sysarch.kiran@gmail.com) · [📸 Instagram](https://www.instagram.com/kiran_0807x) · [🐙 GitHub](https://github.com/Arch-Kiran)

<br/>

---

*Your files should go where you want them.*
*At full speed.*
*Without asking permission.*

</div>
