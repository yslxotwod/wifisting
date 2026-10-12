#!/usr/bin/env python3
"""Minimal X11 clicker using XTest, for verifying lazily-built GUI pages.

No xdotool/wmctrl on this box, but libXtst is present, so XTest is enough
to move the pointer and click. Usage:

    xclick.py X Y            click at absolute screen coordinates
    xclick.py --move X Y     move only
"""
import ctypes
import sys
import time

x11 = ctypes.CDLL("libX11.so.6")
xtst = ctypes.CDLL("libXtst.so.6")

x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
x11.XFlush.argtypes = [ctypes.c_void_p]
x11.XDefaultScreen.argtypes = [ctypes.c_void_p]
x11.XDefaultScreen.restype = ctypes.c_int

xtst.XTestFakeMotionEvent.argtypes = [
    ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong]
xtst.XTestFakeButtonEvent.argtypes = [
    ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]


def main():
    args = [a for a in sys.argv[1:]]
    move_only = False
    if args and args[0] == "--move":
        move_only = True
        args = args[1:]
    if len(args) != 2:
        print(__doc__)
        return 2

    x, y = int(args[0]), int(args[1])
    dpy = x11.XOpenDisplay(b":0")
    if not dpy:
        print("cannot open display :0")
        return 1

    xtst.XTestFakeMotionEvent(dpy, -1, x, y, 0)
    x11.XFlush(dpy)
    time.sleep(0.25)

    if not move_only:
        xtst.XTestFakeButtonEvent(dpy, 1, True, 0)
        x11.XFlush(dpy)
        time.sleep(0.08)
        xtst.XTestFakeButtonEvent(dpy, 1, False, 0)
        x11.XFlush(dpy)

    time.sleep(0.35)
    return 0


if __name__ == "__main__":
    sys.exit(main())
