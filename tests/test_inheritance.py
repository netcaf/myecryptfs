"""
test_inheritance.py — Directory ACL inheritance (SRS §7).

A file with no xattr of its own inherits the ACL from the nearest
ancestor directory that carries a trusted.ecryptfs_acl_id xattr.
The walk goes upward to the eCryptfs mount root.

Layout created by the dir_with_acl fixture:

    VIEW_DIR/
      inh_<pid>_<ns>/          ← lower dir tagged with ACL_ID=6
        file.txt                ← NO xattr; inherits ACL_ID=6
        sub/                    ← NO xattr
          nested.txt            ← NO xattr; inherits ACL_ID=6 (via grandparent)

Files are created BEFORE the directory is tagged so that initial write
operations are not blocked by the ACL.  Inheritance is resolved lazily
on the first read (cached_acl_id == NONE → re-check).

Rules use perm=rx so that traversal (MAY_EXEC) into the directory is
also allowed for permitted processes; for file reads the intersection
with MAY_READ still correctly yields read-only.
"""

import os
import time
import pytest
from helpers import (
    step, run, acl_add, acl_clear, tag_file,
    VIEW_DIR, ENC_DIR,
    CAT, HEAD, TAIL, ROOT,
)

ACL_ID = 6

_counter = 0


def _unique_name():
    global _counter
    _counter += 1
    return f"inh_{os.getpid()}_{_counter}"


@pytest.fixture(autouse=True)
def clean():
    acl_clear(ACL_ID)
    yield
    acl_clear(ACL_ID)


@pytest.fixture
def dir_with_acl():
    """
    Create VIEW_DIR/<name>/ with pre-made child and grandchild files,
    then tag the lower directory with ACL_ID.

    Files are written BEFORE tagging so no ACL blocks their creation.
    Returns dict with keys:
      'view_dir'  — path to the tagged directory
      'file'      — (path, text) for direct child file
      'nested'    — (path, text) for grandchild file (in sub/)
    """
    name     = _unique_name()
    view_dir = f"{VIEW_DIR}/{name}"
    enc_dir  = f"{ENC_DIR}/{name}"
    sub_dir  = f"{view_dir}/sub"

    os.mkdir(view_dir, 0o755)
    os.mkdir(sub_dir,  0o755)

    # Write files BEFORE tagging the directory
    child_text  = f"secret-child-{time.time()}"
    nested_text = f"secret-nested-{time.time()}"
    child_path  = f"{view_dir}/file.txt"
    nested_path = f"{sub_dir}/nested.txt"

    with open(child_path, "w") as fh:
        fh.write(child_text)
    with open(nested_path, "w") as fh:
        fh.write(nested_text)

    # Tag the LOWER directory — inheritance kicks in on next access
    tag_file(enc_dir, ACL_ID)

    yield {
        "view_dir": view_dir,
        "file":     (child_path,  child_text),
        "nested":   (nested_path, nested_text),
    }

    # Teardown: remove files then directories
    for dirpath, dirs, files in os.walk(view_dir, topdown=False):
        for fname in files:
            try:
                os.unlink(os.path.join(dirpath, fname))
            except OSError:
                pass
        try:
            os.rmdir(dirpath)
        except OSError:
            pass


# ── Direct child file tests ───────────────────────────────────────────────

def test_child_inherits_plaintext(dir_with_acl):
    step("file in tagged dir, exe=head rule → plaintext via inheritance")
    acl_add(ACL_ID, 100, "*", "*", HEAD, "rx", "plaintext")
    fpath, text = dir_with_acl["file"]

    result = run(HEAD, fpath, *ROOT)
    assert result.returncode == 0
    assert text.encode() in result.stdout


def test_child_inherits_ciphertext(dir_with_acl):
    step("file in tagged dir, exe=cat rule → ciphertext via inheritance")
    acl_add(ACL_ID, 100, "*", "*", CAT, "rx", "ciphertext")
    fpath, text = dir_with_acl["file"]

    result = run(CAT, fpath, *ROOT)
    assert result.returncode == 0
    assert text.encode() not in result.stdout


def test_child_inherits_deny(dir_with_acl):
    step("file in tagged dir, exe=head rule only → tail has no match → DENY via inheritance")
    acl_add(ACL_ID, 100, "*", "*", HEAD, "rx", "plaintext")
    fpath, _ = dir_with_acl["file"]

    assert run(TAIL, fpath, *ROOT).returncode != 0


# ── Nested (grandchild) file tests ────────────────────────────────────────

def test_nested_inherits_plaintext(dir_with_acl):
    step("file two levels below tagged dir, exe=head rule → plaintext via grandparent inheritance")
    acl_add(ACL_ID, 100, "*", "*", HEAD, "rx", "plaintext")
    fpath, text = dir_with_acl["nested"]

    result = run(HEAD, fpath, *ROOT)
    assert result.returncode == 0
    assert text.encode() in result.stdout


def test_nested_inherits_deny(dir_with_acl):
    step("file two levels below tagged dir, exe=head rule only → tail → DENY via grandparent")
    acl_add(ACL_ID, 100, "*", "*", HEAD, "rx", "plaintext")
    fpath, _ = dir_with_acl["nested"]

    assert run(TAIL, fpath, *ROOT).returncode != 0
