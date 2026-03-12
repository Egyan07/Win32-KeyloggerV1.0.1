# Win32 Keylogger — Advanced Educational Demo
**Coded by Egyan**

A hands-on Windows internals teaching project. Two programs:

| Program | Purpose |
|---|---|
| `keylogger_demo.c` | Demonstrates 10 core Win32 APIs for keyboard capture, persistence, and process inspection |
| `detector.c` | Shows how AV/EDR tools detect the above — the defender's perspective |

> **For educational and authorised security research use only.**
> Only run on machines you own or have explicit written authorisation to test.
> Deploying this without consent is illegal (Computer Misuse Act 1990 (UK), CFAA (US)).

---

## What This Project Teaches

### Win32 APIs in `keylogger_demo.c`

| API | Concept Taught |
|---|---|
| `SetWindowsHookEx(WH_KEYBOARD_LL)` | Global low-level keyboard hook; hook chain; message pump dependency |
| `ToUnicode()` / `GetKeyboardState()` | Correct key → character translation; dead key handling; keyboard layouts |
| `GetWindowTextW()` + `WideCharToMultiByte()` | Unicode window titles; UTF-16 → UTF-8 conversion |
| `GetWindowThreadProcessId()` | Getting PID from a window handle |
| `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` | Least-privilege process access |
| `QueryFullProcessImageNameA()` | Full .exe path from a process handle |
| `CreateMutexA()` + `ERROR_ALREADY_EXISTS` | Kernel-wide named objects; single-instance guard |
| `RegisterHotKey()` + `WM_HOTKEY` | Global hotkeys; message queue integration |
| `GetComputerNameA()` / `GetUserNameA()` | System context retrieval |
| `RegOpenKeyExA()` / `RegSetValueExA()` | HKCU persistence; HKCU vs HKLM access rights |

### Win32 APIs in `detector.c`

| API | Concept Taught |
|---|---|
| `RegEnumValueA()` | Enumerating registry values; autorun detection |
| `CreateToolhelp32Snapshot()` + `Process32FirstW/NextW` | Process enumeration |
| `FindFirstFileA()` / `FindNextFileA()` | Filesystem scanning; wildcard matching |
| `GetFileAttributesA()` | Detecting hidden files |
| `OpenProcessToken()` + `TokenElevation` | Privilege level detection |
| `GetTokenInformation(TokenPrivileges)` | Enumerating process privileges |
| `LookupPrivilegeNameA()` | Translating LUID to privilege name |
| `FindWindowExA()` + `IsWindowVisible()` | Detecting windowless processes |

---

## Project Structure

```
Win32-Keylogger/
├── keylogger_demo.c     # Attacker perspective -- 10 Win32 APIs demonstrated
├── detector.c           # Defender perspective -- how EDRs detect the above
├── Makefile             # Builds both; cross-compile from Kali or native Windows
└── README.md
```

---

## Build Instructions

### Option A — Cross-compile on Kali / Ubuntu (recommended for teaching)

```bash
# Install MinGW cross-compiler
sudo apt update && sudo apt install mingw-w64 -y

# Build everything
make

# Or build individually
make release    # keylogger_demo.exe (stealth, no console)
make debug      # keylogger_demo_debug.exe (console visible -- for testing)
make detector   # detector.exe
```

Transfer the `.exe` files to your Windows VM via USB, shared folder, or `scp`.

### Option B — Compile natively on Windows

Install [WinLibs GCC](https://winlibs.com) or MSYS2, edit the Makefile `CC = gcc`, then:

```cmd
make
```

Or manually:

```cmd
:: Keylogger (release -- no console)
gcc -Wall -O2 keylogger_demo.c -o keylogger_demo.exe -mwindows -luser32 -ladvapi32 -lkernel32

:: Keylogger (debug -- console visible)
gcc -Wall -g keylogger_demo.c -o keylogger_demo_debug.exe -luser32 -ladvapi32 -lkernel32

:: Detector
gcc -Wall -O2 detector.c -o detector.exe -luser32 -ladvapi32 -lkernel32
```

---

## Classroom Workflow

```
Step 1:  make all          (on Kali)
Step 2:  copy *.exe        (to Windows VM)
Step 3:  run keylogger_demo_debug.exe   (debug build -- console visible, confirms hook is alive)
Step 4:  type in any app   (Notepad, browser, etc.)
Step 5:  open C:\Users\Public\logs\keylog_YYYY-MM-DD.txt in a text editor
Step 6:  run detector.exe  (see what evidence it finds)
Step 7:  clean up          (see Removal section below)
```

**Kill switch:** `Ctrl+Shift+F12` stops the keylogger cleanly without Task Manager.

---

## Example Log Output

```
================================================================
 GhostKey Session Log
 Timestamp : 2025-01-15 09:32:11
 Machine   : CLASSROOM-PC01
 User      : student01
 Kill sw.  : Ctrl+Shift+F12
================================================================

[09:32:15] >>> C:\Program Files\Google\Chrome\Application\chrome.exe
           >>> Gmail - Inbox - Google Chrome
hello world[ENTER]

[09:32:44] >>> C:\Windows\System32\notepad.exe
           >>> Untitled - Notepad
test notes here[ENTER]
```

Compared to the basic version, the log now shows:
- **Full process path** (not just window title)
- **UTF-8 BOM** so any editor opens the file correctly
- **Machine and user** in the session header

---

## How It Works (Deep Dive)

### `SetWindowsHookEx(WH_KEYBOARD_LL)` — The Hook

Windows maintains a chain of hooks for each hook type. When you call `SetWindowsHookEx(WH_KEYBOARD_LL, callback, NULL, 0)`:

- `WH_KEYBOARD_LL` — low-level keyboard hook; fires BEFORE the key reaches any application
- `hMod = NULL` — for LL hooks, the callback runs in the **calling process** (not injected)
- `dwThreadId = 0` — global hook, applies to all threads

The hook callback (`KeyboardProc`) is called by Windows via the message queue. This is why the message pump loop is **mandatory** — without `GetMessage()` running, Windows times out the hook after ~5 seconds.

### `ToUnicode()` — Why It Beats a Manual Switch Table

The original basic version had an 80-line switch statement manually mapping VK codes. That approach breaks immediately on non-US keyboards.

`ToUnicode()` is how Windows itself converts virtual keys to characters. Feed it the VK code, scan code, and the current 256-byte key state array, and it returns the correct Unicode character for whatever keyboard layout the user has configured. It handles:

- CapsLock and Shift automatically (from the key state array)
- Dead keys: pressing `^` then `e` correctly produces `ê`
- AltGr: on French keyboards, AltGr+e produces `€`
- International layouts: Arabic, CJK, etc.

### Process Path from Window Handle — The HWND → PID → Path Chain

```c
DWORD pid = 0;
GetWindowThreadProcessId(hwnd, &pid);          // HWND  → PID

HANDLE hProc = OpenProcess(                    // PID   → HANDLE
    PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

DWORD sz = MAX_PATH;
QueryFullProcessImageNameA(hProc, 0, buf, &sz); // HANDLE → path
CloseHandle(hProc);
```

`PROCESS_QUERY_LIMITED_INFORMATION` is the minimum right needed for `QueryFullProcessImageNameA`. Using the minimum right is always better practice than requesting full access.

### Single-Instance Mutex

Named mutexes with the `Global\` prefix exist in the kernel's global namespace — visible across all user sessions. The pattern is:

```c
HANDLE h = CreateMutexA(NULL, TRUE, "Global\\MyName");
if (GetLastError() == ERROR_ALREADY_EXISTS) exit(0);
```

`CreateMutexA` either creates the mutex (returning a new handle) or opens the existing one (also returning a handle, but setting `ERROR_ALREADY_EXISTS`). Either way you get a valid handle, which is why checking `GetLastError` rather than the return value is the correct pattern.

### HKCU Persistence — No Admin Required

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

Windows reads this key on every interactive login and launches every value found. HKCU is always writeable by the current user without elevation. HKLM\...\Run is system-wide but requires admin rights to write.

---

## How `detector.c` Detects This

The detector checks five things:

| Check | What It Finds |
|---|---|
| Run registry scan | `SysAudioSvc` entry in HKCU\Run pointing to a non-standard path |
| Process scan | `keylogger_demo.exe` running from `C:\Users\Public\` or similar |
| File scan | `keylog_YYYY-MM-DD.txt` in `C:\Users\Public\logs\` |
| Privilege check | Whether this detector is running elevated (affects what it can see) |
| Windowless processes | Processes with no visible window running from suspicious paths |

### Why EDR Tools Can Do More

The `detector.c` approach is heuristic. Production EDR systems go further:

- **Kernel callbacks**: Register with `PsSetCreateProcessNotifyRoutine`, `PsSetLoadImageNotifyRoutine` to catch the moment a hook is registered
- **NtQuerySystemInformation(SystemHandleInformation)**: Enumerate all kernel hook objects across all processes
- **ETW (Event Tracing for Windows)**: Subscribe to `Microsoft-Windows-Win32k` ETW provider — emits events on `NtUserSetWindowsHookEx` calls
- **SSDT hooks (legacy)**: Older AV tools patched the System Service Descriptor Table to intercept `NtUserSetWindowsHookEx` in kernel mode

---

## Removal

```cmd
:: 1. Kill the process
taskkill /F /IM keylogger_demo.exe

:: 2. Remove the Run registry entry
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SysAudioSvc" /f

:: 3. Delete the log files
rmdir /s /q C:\Users\Public\logs

:: 4. Delete the binary
del keylogger_demo.exe
```

---

## Defensive Takeaways

- `HKCU\Run` is the first registry key every AV scanner checks. Any persistence here is immediately visible to tools like Sysinternals Autoruns.
- `WH_KEYBOARD_LL` hooks are logged by Windows in the kernel hook table. There is no way to hide them from kernel-mode AV agents.
- Logging to `C:\Users\Public\` is world-readable — a poor operational choice, but obvious for lab work.
- The UTF-8 BOM in the log file is a detectable indicator left by tools that write structured log files.
- A process with no visible window, started from a non-standard path, and present in `HKCU\Run` is trivially flagged by modern EDR heuristics.

---

## Changelog

### v2.0.0 (2026-03-13)
- Fix: `ToUnicode()` dead key double-call implemented — pressing `^` then `e` now correctly produces `ê` on European keyboards
- Fix: `GetWindowTextA` → `GetWindowTextW` + `WideCharToMultiByte` — preserves non-ASCII window titles in the log
- Fix: Manual 80-line `vk_to_string()` switch → `ToUnicodeEx` — handles all keyboard layouts automatically
- Fix: `detector.c` windowless scan O(n×m) → O(n+m) — builds visible-PID set once, no per-process window list rescan
- Add: Single-instance mutex guard via `Global\` named mutex
- Add: `Ctrl+Shift+F12` kill switch via `RegisterHotKey`
- Add: Session header with machine name and username
- Add: Process path alongside window title via `QueryFullProcessImageNameA`
- Add: UTF-8 BOM and binary mode log file
- Add: `detector.c` — companion detection tool showing the defender's perspective
- Add: `Makefile`, cross-compile support for Kali/Ubuntu → Windows

### v1.0.1
- Initial release

## Disclaimer

This project is for **educational purposes only**. It was built to teach Win32 API internals, keyboard hooking mechanics, Windows persistence mechanisms, and detection/defence techniques — the same concepts covered in OSCP, eCPPT, and Windows malware analysis courses.

**Do not deploy on any system without explicit written authorisation.**

---

*Coded by Egyan | Cybersecurity & Windows Internals*
