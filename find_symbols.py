#!/usr/bin/env python3
"""Find Windows Defender versions compiled with symbols"""

import os
import subprocess
import tempfile
from glob import glob

import r2pipe


def find_symbols():
    """Find Windows Defender versions compiled with symbols"""
    f = open("num_syms_mpengine_dll.txt", "w", buffering=1)
    for exe in glob("*.exe"):
        tmp = tempfile.TemporaryDirectory()
        subprocess.run(["cabextract", exe, "-d", tmp.name],
                       capture_output=True)
        dll = os.path.join(tmp.name, "mpengine.dll")
        r2 = r2pipe.open(dll)
        syms = r2.cmd("f~sym.")
        r2.quit()
        syms = syms.splitlines()
        syms = len(syms)
        s = f"{exe} {syms}\n"
        print(s, end="")
        f.write(s)

        #proc = subprocess.run(["exiftool", dll_path], capture_output=True)

        #exif = proc.stdout.splitlines()
        #ver = filter(lambda line: b"Product Version Number" in line, exif)

        #try:
        #    ver = ver.__next__()
        #except StopIteration:
        #    continue

        #ver = ver.split(b" : ")[1]
        #ver = ver.decode("utf-8")

        #print(exe, ver)
        #subprocess.run(["x86_64-w64-mingw32-nm", dll_path])


if __name__ == "__main__":
    find_symbols()
