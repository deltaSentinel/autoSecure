#!/usr/bin/env python3
# =====================================================================
# File: common.py
# Shared helpers for the AutoSecure collector package.
# No schema impact — pure utilities.
# =====================================================================

import os
import re
import shutil
import subprocess


def sh(cmd, timeout=30, ignore_rc=False):
    """Run a command (list form). Return stdout on success, else None."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 or ignore_rc:
            return r.stdout
    except Exception:
        pass
    return None


def sh_bool(cmd, timeout=30):
    """Return True if command exits 0."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


def sh_rc(cmd, timeout=30):
    """Return the raw returncode, or None if the command could not run."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode
    except Exception:
        return None


def read_file(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def stat_octal(path):
    try:
        return format(os.stat(path).st_mode & 0o7777, "o")
    except Exception:
        return None


def which(binname):
    """shutil.which that never raises (PATH can be odd in stripped LXCs)."""
    try:
        return shutil.which(binname)
    except Exception:
        return None


def parse_os_release(path="/etc/os-release"):
    """Return dict of KEY=VALUE pairs from os-release. Empty dict if absent."""
    info = {}
    content = read_file(path)
    if content is None:
        content = read_file("/usr/lib/os-release")
    if content is None:
        return info
    for line in content.splitlines():
        m = re.match(r'^([A-Z_]+)=(.*)$', line)
        if m:
            info[m.group(1)] = m.group(2).strip('"')
    return info

