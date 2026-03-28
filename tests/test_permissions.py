"""
test_permissions.py — Permission bit enforcement (r / w / rw).

Verifies that the perm field in ACL rules correctly controls which
operations (read, write) are allowed, independent of content mode.

The enforcement point is ecryptfs_permission() in inode.c:
  MAY_READ  → requires ECRYPTFS_ACL_PERM_R in decision.perm
  MAY_WRITE → requires ECRYPTFS_ACL_PERM_W in decision.perm

Additional constraint (SRS §2): content=ciphertext forces perm to
read-only even if the rule specifies perm=rw.
"""

import pytest
from helpers import (
    step, run, run_write, acl_add, acl_clear,
    HEAD, DD,
    ROOT,
)

ACL_ID = 7


@pytest.fixture
def protected(make_file):
    return make_file(acl_id=ACL_ID)


@pytest.fixture(autouse=True)
def clean():
    acl_clear(ACL_ID)
    yield
    acl_clear(ACL_ID)


# ── Read permission ───────────────────────────────────────────────────────

def test_perm_r_allows_read(protected):
    step("perm=r, exe=head reads file → read allowed")
    acl_add(ACL_ID, 100, "*", "*", HEAD, "r", "plaintext")
    view, text = protected

    result = run(HEAD, view, *ROOT)
    assert result.returncode == 0
    assert text.encode() in result.stdout


def test_perm_r_denies_write(protected):
    step("perm=r, exe=dd writes file → write denied (MAY_WRITE not in perm)")
    acl_add(ACL_ID, 100, "*", "*", DD, "r", "plaintext")
    view, _ = protected

    assert run_write(view, *ROOT).returncode != 0


# ── Write permission ──────────────────────────────────────────────────────

def test_perm_rw_allows_write(protected):
    step("perm=rw, exe=dd writes file → write allowed")
    acl_add(ACL_ID, 100, "*", "*", DD, "rw", "plaintext")
    view, _ = protected

    assert run_write(view, *ROOT).returncode == 0


def test_perm_w_denies_read(protected):
    step("perm=w only, exe=head reads file → read denied (MAY_READ not in perm)")
    acl_add(ACL_ID, 100, "*", "*", HEAD, "w", "plaintext")
    view, _ = protected

    assert run(HEAD, view, *ROOT).returncode != 0


# ── Ciphertext forces read-only regardless of perm ───────────────────────

def test_ciphertext_perm_rw_denies_write(protected):
    step("perm=rw + content=ciphertext → ciphertext forces read-only → write denied")
    acl_add(ACL_ID, 100, "*", "*", DD, "rw", "ciphertext")
    view, _ = protected

    assert run_write(view, *ROOT).returncode != 0


def test_ciphertext_perm_rw_allows_read(protected):
    step("perm=rw + content=ciphertext → read allowed (but gets raw ciphertext bytes)")
    acl_add(ACL_ID, 100, "*", "*", HEAD, "rw", "ciphertext")
    view, text = protected

    result = run(HEAD, view, *ROOT)
    assert result.returncode == 0
    assert text.encode() not in result.stdout   # ciphertext, not plaintext
