"""
test_basic.py — Executable-based rules (uid/gid wildcarded).

Rules:
  exe=cat  → ciphertext
  exe=head → plaintext
  exe=tail → (no rule) → DENY
"""

import pytest
from helpers import step, run, acl_add, acl_clear, CAT, HEAD, TAIL, ROOT

ACL_ID = 1


@pytest.fixture
def protected(make_file):
    return make_file(acl_id=ACL_ID)


@pytest.fixture(autouse=True)
def rules():
    acl_clear(ACL_ID)
    acl_add(ACL_ID, 100, "*", "*", CAT,  "r", "ciphertext")
    acl_add(ACL_ID,  50, "*", "*", HEAD, "r", "plaintext")
    yield
    acl_clear(ACL_ID)


def test_passthrough(plain_file):
    step("file has no ACL xattr → any exe reads plaintext (pass-through)")
    view, text = plain_file
    result = run(TAIL, view, *ROOT)
    assert result.returncode == 0
    assert text.encode() in result.stdout


def test_head_plaintext(protected):
    step("exe=head matches rule → expect plaintext content")
    view, text = protected
    result = run(HEAD, view, *ROOT)
    assert result.returncode == 0
    assert text.encode() in result.stdout


def test_cat_ciphertext(protected):
    step("exe=cat matches rule → expect raw ciphertext (plaintext must not appear)")
    view, text = protected
    result = run(CAT, view, *ROOT)
    assert result.returncode == 0
    assert text.encode() not in result.stdout


def test_tail_denied(protected):
    step("exe=tail has no matching rule → expect EACCES")
    view, _ = protected
    assert run(TAIL, view, *ROOT).returncode != 0
