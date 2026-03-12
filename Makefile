# =============================================================================
# Makefile  --  Win32 Educational Keylogger + Detector
# Coded by Egyan
#
# Requires MinGW-w64 cross-compiler (Linux/Kali) or native gcc (Windows).
#
# On Kali / Ubuntu:
#   sudo apt update && sudo apt install mingw-w64 -y
#
# On Windows (WinLibs / MSYS2):
#   Replace CC with: CC = gcc
# =============================================================================

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Wall -Wextra -O2 -D_WIN32_WINNT=0x0600
DBGFLAGS = -Wall -g -D_WIN32_WINNT=0x0600

# Libraries:
#   -luser32   : keyboard hooks, window title, hotkey APIs
#   -ladvapi32 : registry APIs, token/privilege APIs
#   -lkernel32 : process/path APIs (implicit but explicit is good practice)
#   -mwindows  : no console window subsystem (release builds only)

KEYLOGGER_SRC  = keylogger_demo.c
KEYLOGGER_EXE  = keylogger_demo.exe
KEYLOGGER_DBG  = keylogger_demo_debug.exe

DETECTOR_SRC   = detector.c
DETECTOR_EXE   = detector.exe

KEYLOGGER_LIBS = -luser32 -ladvapi32 -lkernel32
DETECTOR_LIBS  = -luser32 -ladvapi32 -lkernel32


# =============================================================================
# Targets
# =============================================================================

.PHONY: all release debug detector clean help

all: release detector
	@echo ""
	@echo "  Built:  $(KEYLOGGER_EXE)  (stealth, no console)"
	@echo "  Built:  $(DETECTOR_EXE)   (detection companion)"
	@echo ""
	@echo "  Transfer both .exe files to your Windows test machine."
	@echo "  Run keylogger_demo.exe first, then detector.exe."

# Release keylogger: -mwindows suppresses the console window
release: $(KEYLOGGER_SRC)
	$(CC) $(CFLAGS) $< -o $(KEYLOGGER_EXE) -mwindows $(KEYLOGGER_LIBS)
	@echo "  [OK] $(KEYLOGGER_EXE) -- stealth build (no console)"

# Debug keylogger: console window visible, debug symbols, no optimisation
# Use this to verify the hook is running and see error output
debug: $(KEYLOGGER_SRC)
	$(CC) $(DBGFLAGS) $< -o $(KEYLOGGER_DBG) $(KEYLOGGER_LIBS)
	@echo "  [OK] $(KEYLOGGER_DBG) -- debug build (console visible)"

# Detector: always has a console window (it's a scanner tool)
detector: $(DETECTOR_SRC)
	$(CC) $(CFLAGS) $< -o $(DETECTOR_EXE) $(DETECTOR_LIBS)
	@echo "  [OK] $(DETECTOR_EXE) -- detection companion"

clean:
	rm -f $(KEYLOGGER_EXE) $(KEYLOGGER_DBG) $(DETECTOR_EXE)
	@echo "  Cleaned."

help:
	@echo ""
	@echo "  Usage:"
	@echo "    make             Build release keylogger + detector"
	@echo "    make release     Build keylogger (no console window)"
	@echo "    make debug       Build keylogger (console visible, for testing)"
	@echo "    make detector    Build detector.exe only"
	@echo "    make clean       Remove all .exe files"
	@echo ""
	@echo "  Classroom workflow:"
	@echo "    1. make all"
	@echo "    2. Copy both .exe to a Windows VM"
	@echo "    3. Run keylogger_demo_debug.exe to see it working"
	@echo "    4. Run detector.exe to see how AV tools detect it"
	@echo "    5. Use the removal commands in README.md to clean up"
	@echo ""
