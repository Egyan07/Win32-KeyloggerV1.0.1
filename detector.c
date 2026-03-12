/*
 * detector.c  --  Companion Detection Tool for keylogger_demo.c
 * Coded by Egyan
 *
 * ============================================================
 * PURPOSE
 * ============================================================
 *
 *  This tool shows your colleague the DEFENDER'S perspective:
 *  how AV engines, EDR agents, and forensic tools detect a
 *  keylogger like keylogger_demo.c.
 *
 *  Run this on the same machine as keylogger_demo.exe to see
 *  exactly what evidence it leaves behind.
 *
 * ============================================================
 * WIN32 APIS DEMONSTRATED
 * ============================================================
 *
 *  [1]  RegOpenKeyExA / RegEnumValueA
 *           Enumerate all values under HKCU\...\Run and HKLM\...\Run
 *           to find suspicious autorun entries.
 *           This is the #1 place AV tools look first.
 *
 *  [2]  CreateToolhelp32Snapshot / Process32FirstW / Process32NextW
 *           Enumerate all running processes.  Each PROCESSENTRY32W
 *           gives the EXE name, PID, and parent PID.
 *
 *  [3]  OpenProcess / QueryFullProcessImageNameA
 *           Get the full filesystem path of each running process.
 *           Suspicious paths: %TEMP%, %PUBLIC%, %APPDATA%, etc.
 *
 *  [4]  FindFirstFileA / FindNextFileA
 *           Scan the filesystem for keylog files by pattern.
 *           Matches keylog_YYYY-MM-DD.txt in known locations.
 *
 *  [5]  GetFileAttributesA + FILE_ATTRIBUTE_HIDDEN
 *           Check if files or directories are marked hidden.
 *           Malware often marks its files hidden via attrib.
 *
 *  [6]  OpenProcessToken / GetTokenInformation / LookupPrivilegeName
 *           Enumerate the privileges of a process token.
 *           SeDebugPrivilege in a non-system process is a red flag.
 *
 *  [7]  GetSystemInfo / GetComputerNameA / GetUserNameA
 *           Collect system context for the report header.
 *
 * ============================================================
 * BUILD
 * ============================================================
 *
 *  Release:
 *    x86_64-w64-mingw32-gcc -Wall -Wextra -O2 detector.c \
 *      -o detector.exe -luser32 -ladvapi32 -lkernel32
 *
 *  Run as a standard (non-admin) user to test what unprivileged
 *  tools can see.  Then run as Administrator to compare.
 *
 * ============================================================
 * DISCLAIMER
 * ============================================================
 *
 *  FOR EDUCATIONAL USE ONLY.  This tool reads public system
 *  state only -- no privileged memory access, no kernel calls.
 *  Coded by Egyan
 */

#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── Colours for console output ─────────────────────────────── */
#define COL_RESET   "\033[0m"
#define COL_RED     "\033[31;1m"
#define COL_YELLOW  "\033[33;1m"
#define COL_GREEN   "\033[32;1m"
#define COL_CYAN    "\033[36;1m"
#define COL_BOLD    "\033[1m"

/* ── Suspicious path fragments ──────────────────────────────── */
static const char *SUSPICIOUS_PATH_FRAGMENTS[] = {
    "\\users\\public\\",
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\recycle",
    "\\programdata\\",
    NULL
};

/* ── Suspicious registry value name fragments ───────────────── */
static const char *SUSPICIOUS_NAMES[] = {
    "sysaudio",
    "keylog",
    "ghost",
    "logger",
    "monitor",
    "capture",
    "hook",
    NULL
};

/* ── Known log file directories to scan ──────────────────────── */
static const char *LOG_SCAN_DIRS[] = {
    "C:\\Users\\Public\\logs\\",
    "C:\\Windows\\Temp\\",
    "C:\\Temp\\",
    NULL
};

/* ── Totals for the summary ─────────────────────────────────── */
static int g_registry_hits = 0;
static int g_process_hits  = 0;
static int g_file_hits     = 0;


/* ============================================================
 *  HELPERS
 * ============================================================ */

static void enable_vt100(void)
{
    /* Enable VT100 colour codes on Windows 10 1511+ */
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static void str_tolower(char *s)
{
    for (; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') *s += 32;
    }
}

static BOOL path_is_suspicious(const char *path)
{
    char lower[512] = {0};
    strncpy(lower, path, sizeof(lower) - 1);
    str_tolower(lower);

    for (int i = 0; SUSPICIOUS_PATH_FRAGMENTS[i]; i++) {
        if (strstr(lower, SUSPICIOUS_PATH_FRAGMENTS[i])) return TRUE;
    }
    return FALSE;
}

static BOOL name_is_suspicious(const char *name)
{
    char lower[256] = {0};
    strncpy(lower, name, sizeof(lower) - 1);
    str_tolower(lower);

    for (int i = 0; SUSPICIOUS_NAMES[i]; i++) {
        if (strstr(lower, SUSPICIOUS_NAMES[i])) return TRUE;
    }
    return FALSE;
}

static void print_separator(void)
{
    printf(COL_CYAN "------------------------------------------------------------\n" COL_RESET);
}

static void print_header(const char *title)
{
    printf("\n" COL_BOLD COL_CYAN
           "============================================================\n"
           "  %s\n"
           "============================================================\n"
           COL_RESET, title);
}


/* ============================================================
 *  [1] SCAN AUTORUN REGISTRY KEYS
 *
 *  Both HKCU (no admin) and HKLM (admin needed to write) Run
 *  keys are checked.  For each value we:
 *    - Print the name and data
 *    - Flag it SUSPICIOUS if the name or path matches our list
 *    - Show WHERE to delete it if it looks bad
 *
 *  This is exactly what Autoruns.exe (Sysinternals) and most
 *  AV scanners do as their first check.
 * ============================================================ */
static void scan_run_keys(void)
{
    print_header("[1] AUTORUN REGISTRY KEYS");

    printf(COL_BOLD "  Technique: " COL_RESET
           "RegOpenKeyExA + RegEnumValueA\n\n");

    struct { HKEY root; const char *name; } KEYS[] = {
        { HKEY_CURRENT_USER,
          "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE,
          "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE,
          "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { 0, NULL }
    };

    for (int ki = 0; KEYS[ki].name; ki++) {
        const char *hive = (KEYS[ki].root == HKEY_CURRENT_USER) ? "HKCU" : "HKLM";
        printf("  Scanning: %s\\%s\n", hive, KEYS[ki].name);

        HKEY hKey;
        LONG r = RegOpenKeyExA(KEYS[ki].root, KEYS[ki].name,
                               0, KEY_READ, &hKey);
        if (r != ERROR_SUCCESS) {
            printf("    (Cannot open - insufficient rights or key absent)\n");
            continue;
        }

        /* Enumerate all values under this key */
        DWORD idx = 0;
        char  valName[256];
        BYTE  valData[512];
        DWORD nameLen, dataLen, valType;

        int found_any = 0;
        while (1) {
            nameLen = sizeof(valName);
            dataLen = sizeof(valData) - 1;
            memset(valName, 0, sizeof(valName));
            memset(valData, 0, sizeof(valData));

            r = RegEnumValueA(hKey, idx++, valName, &nameLen,
                              NULL, &valType, valData, &dataLen);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            if (valType != REG_SZ && valType != REG_EXPAND_SZ) continue;

            found_any = 1;
            const char *path_str = (const char *)valData;

            BOOL suspicious = name_is_suspicious(valName) ||
                              path_is_suspicious(path_str);

            if (suspicious) {
                printf(COL_RED "    [SUSPICIOUS] " COL_RESET);
                g_registry_hits++;
            } else {
                printf(COL_GREEN "    [OK]         " COL_RESET);
            }

            printf("%-30s  =>  %s\n", valName, path_str);

            if (suspicious) {
                printf("    " COL_YELLOW "    Removal: reg delete \"%s\\%s\" /v \"%s\" /f\n"
                       COL_RESET,
                       hive, KEYS[ki].name, valName);
            }
        }

        if (!found_any) printf("    (No entries found)\n");
        RegCloseKey(hKey);
        print_separator();
    }
}


/* ============================================================
 *  [2] ENUMERATE RUNNING PROCESSES
 *
 *  CreateToolhelp32Snapshot takes a snapshot of all processes.
 *  Process32FirstW / Process32NextW iterate over it.
 *
 *  For each process we:
 *    - Get the full image path via QueryFullProcessImageNameA
 *    - Flag it if the path is in a suspicious location
 *    - Flag it if the process name matches known indicators
 *    - Show the PID for correlation with other tools
 *
 *  Note: Protected processes (lsass, csrss, etc.) will return
 *  ERROR_ACCESS_DENIED on OpenProcess -- expected behaviour.
 * ============================================================ */
static void enumerate_processes(void)
{
    print_header("[2] RUNNING PROCESSES");

    printf(COL_BOLD "  Technique: " COL_RESET
           "CreateToolhelp32Snapshot + QueryFullProcessImageNameA\n\n");

    /* TH32CS_SNAPPROCESS: include all processes in the snapshot */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("  ERROR: CreateToolhelp32Snapshot failed (%lu)\n",
               GetLastError());
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return;
    }

    do {
        DWORD pid = pe.th32ProcessID;
        if (pid == 0 || pid == 4) continue;   /* Idle + System: skip */

        /* Open with minimal rights */
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                   FALSE, pid);

        char fullPath[512] = {0};
        if (hProc) {
            DWORD sz = sizeof(fullPath);
            QueryFullProcessImageNameA(hProc, 0, fullPath, &sz);
            CloseHandle(hProc);
        } else {
            strncpy(fullPath, "(protected/access denied)", sizeof(fullPath) - 1);
        }

        /* Convert wide exe name to narrow for suspicious check */
        char exeName[260] = {0};
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1,
                            exeName, sizeof(exeName) - 1, NULL, NULL);

        BOOL suspicious = path_is_suspicious(fullPath) ||
                          name_is_suspicious(exeName);

        if (suspicious) {
            printf(COL_RED   "  [SUSPICIOUS] " COL_RESET);
            g_process_hits++;
        } else {
            /* Only print suspicious ones to reduce noise.
             * Comment this out to see ALL processes. */
            continue;
        }

        printf("PID %-6lu  %-30s\n", (unsigned long)pid, exeName);
        printf("             Path: %s\n", fullPath);
        printf("             Kill: taskkill /F /PID %lu\n\n",
               (unsigned long)pid);

    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);

    if (g_process_hits == 0) {
        printf("  No suspicious processes found by path/name heuristics.\n");
        printf("  " COL_YELLOW "NOTE: " COL_RESET
               "keylogger_demo.exe disguises itself as 'SysAudioSvc'.\n"
               "  Look for processes in non-standard paths or with\n"
               "  no associated window (Task Manager -> Details tab).\n");
    }
}


/* ============================================================
 *  [3] SCAN FILESYSTEM FOR LOG FILES
 *
 *  FindFirstFileA / FindNextFileA search a directory for files
 *  matching a wildcard pattern.
 *
 *  We scan locations commonly used by keyloggers:
 *    C:\Users\Public\logs\
 *    C:\Windows\Temp\
 *    C:\Temp\
 *
 *  Files matching keylog_*.txt are a strong indicator.
 *  We also check GetFileAttributesA for the FILE_ATTRIBUTE_HIDDEN
 *  flag -- some malware hides its log files.
 * ============================================================ */
static void scan_log_files(void)
{
    print_header("[3] FILESYSTEM SCAN FOR LOG FILES");

    printf(COL_BOLD "  Technique: " COL_RESET
           "FindFirstFileA + FindNextFileA\n\n");

    for (int i = 0; LOG_SCAN_DIRS[i]; i++) {
        char pattern[512];
        snprintf(pattern, sizeof(pattern), "%s*", LOG_SCAN_DIRS[i]);

        printf("  Scanning: %s\n", LOG_SCAN_DIRS[i]);

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(pattern, &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            printf("    (Directory not found or empty)\n");
            print_separator();
            continue;
        }

        int found = 0;
        do {
            /* Skip . and .. */
            if (strcmp(fd.cFileName, ".") == 0 ||
                strcmp(fd.cFileName, "..") == 0) continue;

            /* Build full path */
            char fullPath[512];
            snprintf(fullPath, sizeof(fullPath), "%s%s",
                     LOG_SCAN_DIRS[i], fd.cFileName);

            char lower[512] = {0};
            strncpy(lower, fd.cFileName, sizeof(lower) - 1);
            str_tolower(lower);

            BOOL is_keylog = (strncmp(lower, "keylog_", 7) == 0) ||
                             (strstr(lower, "keylog")  != NULL) ||
                             (strstr(lower, "ghostkey") != NULL);

            BOOL is_hidden = (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;

            if (is_keylog || is_hidden) {
                g_file_hits++;
                found++;

                /* Calculate file size from DWORD high/low parts */
                ULONGLONG sz = ((ULONGLONG)fd.nFileSizeHigh << 32) |
                               fd.nFileSizeLow;

                printf(COL_RED "    [FOUND]  " COL_RESET
                       "%-40s  %llu bytes%s\n",
                       fd.cFileName, sz,
                       is_hidden ? COL_YELLOW " [HIDDEN]" COL_RESET : "");
                printf("            Full path: %s\n", fullPath);
                printf("            Delete:    del \"%s\"\n", fullPath);
            }

        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);

        if (!found) printf("    (No keylog files found here)\n");
        print_separator();
    }
}


/* ============================================================
 *  [4] CHECK CURRENT PROCESS PRIVILEGE LEVEL
 *
 *  OpenProcessToken retrieves the access token for our process.
 *  GetTokenInformation with TokenElevation tells us if this
 *  process is running elevated (as Administrator).
 *
 *  This teaches students WHY some checks fail (e.g. can't open
 *  HKLM keys for writing without admin), and why attackers
 *  try to escalate privileges.
 *
 *  We also check for SeDebugPrivilege specifically -- a process
 *  that holds SeDebugPrivilege can open any other process,
 *  which is why it's a key privilege for both attackers and
 *  defenders (and why Mimikatz requests it first).
 * ============================================================ */
static void check_detector_privileges(void)
{
    print_header("[4] CURRENT PROCESS PRIVILEGES");

    printf(COL_BOLD "  Technique: " COL_RESET
           "OpenProcessToken + TokenElevation + TokenPrivileges\n\n");

    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_QUERY, &hToken)) {
        printf("  OpenProcessToken failed (%lu)\n", GetLastError());
        return;
    }

    /* Check elevation */
    TOKEN_ELEVATION elev;
    DWORD retLen = 0;
    if (GetTokenInformation(hToken, TokenElevation,
                            &elev, sizeof(elev), &retLen)) {
        if (elev.TokenIsElevated) {
            printf("  Elevation: " COL_GREEN "ELEVATED (Administrator)\n" COL_RESET);
            printf("  -> Full HKLM access, can open most processes\n");
        } else {
            printf("  Elevation: " COL_YELLOW "NOT elevated (standard user)\n" COL_RESET);
            printf("  -> HKCU scan works; HKLM writes will fail\n");
            printf("  -> Some processes will show (access denied)\n");
            printf("  -> Re-run as Administrator for complete scan\n");
        }
    }

    /* Enumerate privileges */
    printf("\n  Checking for SeDebugPrivilege (key for process inspection):\n");

    DWORD privSize = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &privSize);
    TOKEN_PRIVILEGES *privs = (TOKEN_PRIVILEGES *)malloc(privSize);
    if (privs && GetTokenInformation(hToken, TokenPrivileges,
                                      privs, privSize, &privSize)) {
        for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
            char privName[128] = {0};
            DWORD nameLen = sizeof(privName);
            LookupPrivilegeNameA(NULL,
                                 &privs->Privileges[i].Luid,
                                 privName, &nameLen);
            if (strcmp(privName, "SeDebugPrivilege") == 0) {
                BOOL enabled = (privs->Privileges[i].Attributes &
                                SE_PRIVILEGE_ENABLED) != 0;
                printf("  SeDebugPrivilege: %s\n",
                       enabled
                         ? COL_GREEN "ENABLED" COL_RESET
                         : COL_YELLOW "present but not enabled" COL_RESET);
            }
        }
    }
    if (privs) free(privs);

    CloseHandle(hToken);
}


/* ============================================================
 *  [5] HOOKING DETECTION -- CONCEPTUAL EXPLANATION
 *
 *  Detecting SetWindowsHookEx(WH_KEYBOARD_LL) from another
 *  process is non-trivial from user mode, but EDR agents use
 *  several techniques.  We explain them here as teaching material.
 *
 *  We also check an indirect indicator: find processes that
 *  have no visible window, since keylogger_demo runs with
 *  -mwindows and has no user interface.
 * ============================================================ */
static void hooking_detection_info(void)
{
    print_header("[5] KEYBOARD HOOK DETECTION -- HOW EDRs DO IT");

    printf(
      "  How AV/EDR tools detect WH_KEYBOARD_LL hooks:\n\n"
      "  " COL_BOLD "A. Kernel callback hooks (most reliable)\n" COL_RESET
      "     The kernel maintains a global hook table. EDR kernel drivers\n"
      "     (KMDF) enumerate it via internal structures. This is how\n"
      "     Windows Defender and CrowdStrike Falcon detect global hooks.\n\n"

      "  " COL_BOLD "B. NtQuerySystemInformation (SystemHandleInformation)\n" COL_RESET
      "     Enumerate all kernel handles across all processes. Hook objects\n"
      "     appear as handle type 19 (Hook) in the handle table.\n"
      "     Used by tools like Process Hacker / System Informer.\n\n"

      "  " COL_BOLD "C. ETW (Event Tracing for Windows)\n" COL_RESET
      "     Microsoft-Windows-Win32k provider emits events when\n"
      "     SetWindowsHookEx is called. Subscribe via TDH API.\n"
      "     Used by Elastic EDR and Microsoft Defender for Endpoint.\n\n"

      "  " COL_BOLD "D. API hooking (user mode)\n" COL_RESET
      "     Some AV tools inject a DLL into every process and hook\n"
      "     SetWindowsHookEx in ntdll/user32 to intercept registration.\n\n"

      "  " COL_BOLD "E. Heuristic: windowless processes\n" COL_RESET
      "     A process with no visible window that runs as the current user\n"
      "     and starts from a non-standard path is suspicious.\n"
      "     keylogger_demo.exe matches this profile exactly.\n"
    );

    print_separator();

    /* Check for windowless processes in non-standard paths.
     *
     * Performance fix: the naive approach scans the entire window list
     * once per suspicious process -- O(n_processes * n_windows).
     * On a typical desktop that is hundreds of processes * hundreds of
     * windows = tens of thousands of GetWindowThreadProcessId calls.
     *
     * Better approach (O(n_windows + n_processes)):
     *   Pass 1 -- enumerate ALL top-level windows ONCE and build a
     *             lookup table of PIDs that own at least one visible window.
     *   Pass 2 -- for each suspicious process, look up its PID in the table.
     *
     * We use a fixed-size array (MAX_VISIBLE_PIDS) as a simple hash set.
     * 1024 slots is more than enough for any desktop workload.             */

    printf("\n  Scanning for windowless processes in suspicious paths:\n\n");

#define MAX_VISIBLE_PIDS 1024
    DWORD visible_pids[MAX_VISIBLE_PIDS];
    int   visible_count = 0;

    /* Pass 1: single walk of all top-level windows */
    {
        HWND hwnd = NULL;
        while ((hwnd = FindWindowExA(NULL, hwnd, NULL, NULL)) != NULL) {
            if (!IsWindowVisible(hwnd)) continue;
            DWORD owner_pid = 0;
            GetWindowThreadProcessId(hwnd, &owner_pid);
            if (!owner_pid) continue;

            /* Insert into visible set (skip duplicates) */
            BOOL already = FALSE;
            for (int k = 0; k < visible_count; k++) {
                if (visible_pids[k] == owner_pid) { already = TRUE; break; }
            }
            if (!already && visible_count < MAX_VISIBLE_PIDS)
                visible_pids[visible_count++] = owner_pid;
        }
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    int found = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            if (pid == 0 || pid == 4) continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                       FALSE, pid);
            if (!hProc) continue;

            char fullPath[512] = {0};
            DWORD sz = sizeof(fullPath);
            QueryFullProcessImageNameA(hProc, 0, fullPath, &sz);
            CloseHandle(hProc);

            if (!path_is_suspicious(fullPath)) continue;

            /* Pass 2: O(visible_count) lookup -- typically < 100 entries */
            BOOL has_window = FALSE;
            for (int k = 0; k < visible_count; k++) {
                if (visible_pids[k] == pid) { has_window = TRUE; break; }
            }

            if (!has_window) {
                char exeName[260] = {0};
                WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1,
                                    exeName, sizeof(exeName) - 1, NULL, NULL);
                printf(COL_RED "  [SUSPICIOUS] " COL_RESET
                       "PID %-6lu  %-30s  (no window)\n"
                       "               Path: %s\n\n",
                       (unsigned long)pid, exeName, fullPath);
                found++;
            }

        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);

    if (!found) {
        printf("  No windowless processes found in suspicious paths.\n");
    }
}


/* ============================================================
 *  REPORT SUMMARY
 * ============================================================ */
static void print_summary(void)
{
    print_header("DETECTION SUMMARY");

    time_t now = time(NULL);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S",
             localtime(&now));

    printf("  Scan time : %s\n\n", timebuf);
    printf("  Registry hits  : %s%d%s\n",
           g_registry_hits ? COL_RED : COL_GREEN,
           g_registry_hits,
           COL_RESET);
    printf("  Process hits   : %s%d%s\n",
           g_process_hits  ? COL_RED : COL_GREEN,
           g_process_hits,
           COL_RESET);
    printf("  Log file hits  : %s%d%s\n",
           g_file_hits     ? COL_RED : COL_GREEN,
           g_file_hits,
           COL_RESET);

    int total = g_registry_hits + g_process_hits + g_file_hits;
    printf("\n");
    if (total > 0) {
        printf(COL_RED "  RESULT: %d indicator(s) found."
               "  System is LIKELY COMPROMISED.\n" COL_RESET, total);
        printf("\n  Remediation steps:\n"
               "  1. Kill the process (taskkill /F /IM <name>)\n"
               "  2. Remove the Run registry entry (reg delete ...)\n"
               "  3. Delete the log files (del C:\\Users\\Public\\logs\\*)\n"
               "  4. Search for other copies with: dir /s /b <name>.exe\n"
               "  5. Reboot and re-scan to confirm clean\n");
    } else {
        printf(COL_GREEN "  RESULT: No indicators found by these heuristics.\n"
               COL_RESET);
        printf("  NOTE: A well-disguised keylogger may still be present.\n"
               "  For authoritative results, use Sysinternals Autoruns\n"
               "  and Process Monitor on the target machine.\n");
    }
    printf("\n");
}


/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void)
{
    enable_vt100();

    printf(COL_BOLD COL_CYAN
           "\n"
           "  ================================================================\n"
           "  GhostKey Detector  --  Companion to keylogger_demo.c\n"
           "  Coded by Egyan\n"
           "  ================================================================\n"
           "\n"
           "  This tool demonstrates how EDRs and AV engines detect\n"
           "  low-level keyboard loggers via Win32 APIs.\n"
           "  Run this on the same machine as keylogger_demo.exe\n"
           "  to see the indicators it leaves behind.\n"
           COL_RESET "\n");

    scan_run_keys();
    enumerate_processes();
    scan_log_files();
    check_detector_privileges();
    hooking_detection_info();
    print_summary();

    printf("Press Enter to exit...");
    getchar();
    return 0;
}
