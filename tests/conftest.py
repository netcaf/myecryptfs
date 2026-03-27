"""
conftest.py — pytest fixtures shared across all test files.
Loaded automatically by pytest; no imports needed in test files.
"""

import logging
import os
import subprocess
import time
import pytest
from helpers import VIEW_DIR, ENC_DIR, CTRL, tag_file

_log = logging.getLogger("ecryptfs")

MODULE_PATH    = "/home/pi/ecryptfs/ecryptfs.ko"
ACL_DEBUGFS    = "/sys/kernel/debug/ecryptfs_acl"   # exists only with our module

# Mount options must match r.sh exactly
_MOUNT_OPTS = (
    "key=passphrase:passphrase_passwd=Bicdroid123,"
    "ecryptfs_cipher=aes,"
    "ecryptfs_key_bytes=16,"
    "ecryptfs_passthrough=n,"
    "ecryptfs_enable_filename_crypto=n"
)

def _our_module_loaded() -> bool:
    """True only when OUR ecryptfs (with ACL support) is loaded."""
    return os.path.isdir(ACL_DEBUGFS)

def _unload_module():
    _log.info("  rmmod    : unloading existing ecryptfs")
    subprocess.run(["rmmod", "ecryptfs"], check=True)
    _log.info("  rmmod    : OK")

def _load_module():
    _log.info(f"  insmod   : loading {MODULE_PATH}")
    subprocess.run(["insmod", MODULE_PATH], check=True)
    _log.info("  insmod   : OK")

def _umount():
    _log.info(f"  umount   : {VIEW_DIR}")
    subprocess.run(["umount", VIEW_DIR], check=True)
    _log.info("  umount   : OK")

def _mount():
    _log.info(f"  mount    : {ENC_DIR} → {VIEW_DIR}")
    subprocess.run(
        ["mount", "-t", "ecryptfs", ENC_DIR, VIEW_DIR, "-o", _MOUNT_OPTS],
        check=True
    )
    _log.info("  mount    : OK")

# ── Session guard + auto-load + auto-mount ────────────────────────────────
# Order matters:
#   1. insmod our module  — creates /sys/kernel/debug/ecryptfs_acl/
#   2. mount              — creates /sys/kernel/debug/ecryptfs_acl/0/control

@pytest.fixture(scope="session", autouse=True)
def require_root():
    if os.geteuid() != 0:
        pytest.exit("Must run as root:  sudo python3 -m pytest tests/ -v")

    if not _our_module_loaded():
        try:
            # System ecryptfs may be loaded — unload it first
            if os.path.exists("/sys/module/ecryptfs"):
                if os.path.ismount(VIEW_DIR):
                    _umount()
                _unload_module()
            _load_module()
        except subprocess.CalledProcessError as e:
            pytest.exit(f"Failed to load module: {e} — run: cd ~/ecryptfs && make")

    if not os.path.ismount(VIEW_DIR):
        try:
            _mount()
        except subprocess.CalledProcessError as e:
            pytest.exit(f"Auto-mount failed: {e}")

    if not os.access(CTRL, os.W_OK):
        pytest.exit(f"{CTRL} not writable — ACL debugfs not initialized")

# ── File factory ──────────────────────────────────────────────────────────

@pytest.fixture
def make_file():
    """
    Factory fixture — call make_file(acl_id) to create a test file.
    Returns (view_path, known_text).  All created files are deleted on teardown.

      make_file(acl_id=0)  →  no xattr (pass-through, no ACL)
      make_file(acl_id=N)  →  tagged with trusted.ecryptfs_acl_id = N
    """
    created = []

    def _make(acl_id: int = 0):
        name      = f"_t_{os.getpid()}_{int(time.time())}"
        view_path = f"{VIEW_DIR}/{name}"
        enc_path  = f"{ENC_DIR}/{name}"
        text      = f"secret-{time.time()}"

        with open(view_path, "w") as f:
            f.write(text)
        if acl_id > 0:
            tag_file(enc_path, acl_id)

        created.append(view_path)
        return view_path, text

    yield _make

    for path in created:
        try:
            os.unlink(path)
        except OSError:
            pass

# ── Shortcut: file with no ACL (used by passthrough tests) ───────────────

@pytest.fixture
def plain_file(make_file):
    return make_file(acl_id=0)
