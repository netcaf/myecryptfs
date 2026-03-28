"""
helpers.py — utilities and constants shared across all ACL tests.
No pytest dependency; import freely from any test file.
"""

import logging
import os
import struct
import subprocess

# ── Logger ───────────────────────────────────────────────────────────────

_log = logging.getLogger("ecryptfs")

# ── Paths ────────────────────────────────────────────────────────────────

VIEW_DIR = "/testbase/data.view"
ENC_DIR  = "/testbase/data.enc"
CTRL     = "/sys/kernel/debug/ecryptfs_acl/0/control"
RULES    = "/sys/kernel/debug/ecryptfs_acl/0/rules"

# ── Test binaries ─────────────────────────────────────────────────────────

CAT  = "/usr/bin/cat"
HEAD = "/usr/bin/head"
TAIL = "/usr/bin/tail"

# ── User identities (uid, gid) ────────────────────────────────────────────

ROOT      = (0,    0)
PI        = (1000, 1000)
INSPECTOR = (1001, 1001)

_USER_NAMES = {0: "root", 1000: "pi", 1001: "inspector"}

# ── Step helper ───────────────────────────────────────────────────────────

def step(msg: str):
    """Log a test-level description of what is being verified."""
    _log.info(f"  scenario : {msg}")

# ── ACL control ──────────────────────────────────────────────────────────

def acl_write(cmd: str):
    """Send a raw command to the debugfs control file (unbuffered)."""
    with open(CTRL, "wb", buffering=0) as f:
        f.write(cmd.encode())

def acl_add(acl_id, priority, uid, gid, proc, perm, content):
    _log.info(
        f"  rule     : acl_id={acl_id} prio={priority}"
        f"  uid={uid} gid={gid}"
        f"  exe={os.path.basename(proc)}"
        f"  → {content}"
    )
    acl_write(f"add {acl_id} {priority} {uid} {gid} {proc} {perm} {content}\n")

def acl_clear(acl_id):
    try:
        acl_write(f"clear {acl_id}\n")
    except OSError:
        pass

def rules_dump() -> str:
    with open(RULES) as f:
        return f.read()

# ── File helpers ──────────────────────────────────────────────────────────

def tag_file(enc_path: str, acl_id: int):
    """Write trusted.ecryptfs_acl_id (big-endian uint16) onto the lower file."""
    os.setxattr(enc_path, "trusted.ecryptfs_acl_id", struct.pack(">H", acl_id))

def run(binary: str, path: str, uid: int = 0, gid: int = 0) -> subprocess.CompletedProcess:
    """
    Run binary against path as the given uid/gid.
    Uses preexec_fn (fork+setuid+exec) so the kernel sees the correct
    uid and exe path — no sudo wrapper needed.
    Note: gid must be set before uid (cannot setgid after dropping root).
    """
    user = _USER_NAMES.get(uid, f"uid={uid}")
    _log.info(
        f"  command  : {user} (uid={uid} gid={gid})"
        f"  runs {os.path.basename(binary)}"
    )

    def _set_ids():
        os.setgid(gid)
        os.setuid(uid)

    result = subprocess.run([binary, path], capture_output=True, preexec_fn=_set_ids)
    _log.info(f"  result   : exit={result.returncode}")
    return result

DD = "/bin/dd"

def run_write(path: str, uid: int = 0, gid: int = 0) -> subprocess.CompletedProcess:
    """
    Try to open path for writing as the given uid/gid.
    Uses dd to open the file O_WRONLY without changing its content
    (count=0 writes zero bytes).  The kernel sees dd as the exe.
    """
    user = _USER_NAMES.get(uid, f"uid={uid}")
    _log.info(
        f"  command  : {user} (uid={uid} gid={gid})"
        f"  runs dd (write) → {os.path.basename(path)}"
    )

    def _set_ids():
        os.setgid(gid)
        os.setuid(uid)

    result = subprocess.run(
        [DD, f"of={path}", "if=/dev/null", "bs=1", "count=0"],
        capture_output=True, preexec_fn=_set_ids
    )
    _log.info(f"  result   : exit={result.returncode}")
    return result
