# Win32 Keylogger — Educational Demo
**Coded by Egyan**

A Windows keylogger written in C using the Win32 API, built as a hands-on study of low-level keyboard hooking, registry persistence, and Win32 programming concepts.

> ⚠️ **For educational and authorised security research use only.**  
> Only run this on machines you own or have explicit written permission to test on.  
> Deploying this on any system without the owner's consent is illegal.

---

## What This Demonstrates

This project is a practical example of several core Windows internals and Win32 API concepts:

| Concept | API / Technique |
|---|---|
| System-wide keyboard hook | `SetWindowsHookEx(WH_KEYBOARD_LL)` |
| Message pump | `GetMessage` / `DispatchMessage` |
| Active window detection | `GetForegroundWindow` + `GetWindowTextA` |
| Virtual key code mapping | Custom `vk_to_string()` |
| Registry persistence | `RegSetValueExA` to `HKCU\Run` |
| Stealth compile flag | `-mwindows` (suppresses console window) |
| Log rotation | `time()` + `localtime()` |

These are the same primitives studied in Windows internals courses, OSCP labs, and malware analysis training.

---

## Features

- Low-level keyboard hook via `SetWindowsHookEx(WH_KEYBOARD_LL)`
- Active window capture — logs which app you're typing in
- Timestamps on every window switch
- Daily log rotation — new file per day (`keylog_YYYY-MM-DD.txt`)
- Full key mapping — A-Z, 0-9, symbols, special keys labeled in `[BRACKETS]`
- Registry persistence — auto-starts on login (HKCU, no admin needed)
- Optional stealth build — no console window

---

## Build Instructions

### Option A — Cross-compile on Kali Linux (recommended)

```bash
# Install the Windows cross-compiler
sudo apt update && sudo apt install mingw-w64 -y

# Compile
make

# Or manually
x86_64-w64-mingw32-gcc -Wall -O2 keylogger_demo.c -o keylogger_demo.exe -mwindows -luser32 -ladvapi32
```

Transfer `keylogger_demo.exe` to your Windows test machine via USB or shared folder.

### Option B — Compile natively on Windows

Install [WinLibs GCC](https://winlibs.com), add it to PATH, then:

```cmd
gcc -Wall -O2 keylogger_demo.c -o keylogger_demo.exe -mwindows -luser32 -ladvapi32
```

### Debug Build (console window visible)

Useful for confirming the hook is running during testing:

```bash
# Kali
make debug

# Windows
gcc -Wall -g keylogger_demo.c -o keylogger_demo_debug.exe -luser32 -ladvapi32
```

---

## Running It

```cmd
keylogger_demo.exe
```

No console window appears in the release build. Logs are written to:

```
C:\Users\Public\logs\keylog_YYYY-MM-DD.txt
```

---

## Example Log Output

```
════════════════════════════════
Session started: 2025-01-15 09:32:11
════════════════════════════════

[09:32:15] ── Window: Google Chrome ──
hello world[ENTER]

[09:32:44] ── Window: Notepad - untitled ──
some notes here[ENTER]
```

---

## Removing It Completely

```cmd
:: Remove from startup registry
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "keylogger_demo" /f

:: Delete logs
rmdir /s /q C:\Users\Public\logs

:: Delete the binary
del keylogger_demo.exe
```

---

## How It Works

### Keyboard Hook
`SetWindowsHookEx(WH_KEYBOARD_LL)` installs a system-wide hook. Windows calls `KeyboardProc` for every key event on the system, regardless of which process is in focus. The message pump (`GetMessage` loop) keeps the hook alive.

### Window Detection
On each keystroke, `GetForegroundWindow()` + `GetWindowTextA()` check if the active window has changed. If it has, a new header is written to the log giving context to what was being typed where.

### Key Mapping
Virtual key codes (VK_*) are converted to readable strings by `vk_to_string()`. Shift and CapsLock states are checked with `GetAsyncKeyState` and `GetKeyState` for correct character mapping.

### Registry Persistence
`RegSetValueExA` writes the full exe path to `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. This key is read by Windows on every login — no admin rights required (HKCU vs HKLM).

### Log Rotation
`open_log_for_today()` is called on every keystroke. It compares today's date string to the currently open file's date and opens a new file if midnight has passed.

---

## Project Structure

```
win32-keylogger/
├── keylogger_demo.c     # Main source
├── Makefile             # Cross-compile on Kali
└── README.md
```

---

## Defensive Takeaways

Understanding how this works helps with detection and defence:

- `WH_KEYBOARD_LL` hooks are detectable — security tools scan for processes with global hooks via `EnumWindows` and the hook chain
- The `HKCU\Run` registry key is one of the first places AV/EDR tools look for persistence
- Log files in `C:\Users\Public\` are world-readable — a poor choice for a real attacker, but obvious for a lab
- Process names disguised as system components are a common red team technique — knowing this helps defenders build better allowlists

---

## Disclaimer

This project is for **educational purposes only**. It was built to study Win32 API internals, keyboard hooking mechanics, and Windows persistence mechanisms — the same concepts covered in ethical hacking certifications (OSCP, CEH) and malware analysis courses.

**Do not use this on any system you do not own or have explicit written authorisation to test.**

---

## License

MIT License — free to use for learning and research.

---

*Built by Egyan | Cybersecurity & Windows Internals*
