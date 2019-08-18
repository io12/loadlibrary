#!/usr/bin/env python3
"""Find Windows Defender versions compiled with symbols"""

import subprocess
import tempfile
from glob import glob
from os import path


def find_symbols():
    """Find Windows Defender versions compiled with symbols"""
    for exe in glob("*.exe"):
        tmp = tempfile.TemporaryDirectory()
        subprocess.run(["cabextract", exe, "-d", tmp.name],
                       capture_output=True)
        dll_path = path.join(tmp.name, "mpengine.dll")
        proc = subprocess.run(["exiftool", dll_path], capture_output=True)

        exif = proc.stdout.splitlines()
        ver = filter(lambda line: b"Product Version Number" in line, exif)

        try:
            ver = ver.__next__()
        except StopIteration:
            continue

        ver = ver.split(b" : ")[1]
        ver = ver.decode("utf-8")

        print(exe, ver)
        #subprocess.run(["x86_64-w64-mingw32-nm", dll_path])


if __name__ == "__main__":
    find_symbols()
