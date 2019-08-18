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
        subprocess.call(["cabextract", exe, "-d", tmp.name])
        subprocess.call(
            ["x86_64-w64-mingw32-nm",
             path.join(tmp.name, "mpengine.dll")])


if __name__ == "__main__":
    find_symbols()
