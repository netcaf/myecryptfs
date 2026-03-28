"""
test_gid.py — GID-based ACL rules.

Verifies that rules matching on a specific gid (inspector=1001)
allow that group through and deny everyone else.
"""

import pytest
from helpers import step, run, acl_add, acl_clear, HEAD, CAT, PI, INSPECTOR

ACL_ID = 3


@pytest.fixture
def protected(make_file):
    return make_file(acl_id=ACL_ID)


@pytest.fixture(autouse=True)
def clean():
    acl_clear(ACL_ID)
    yield
    acl_clear(ACL_ID)


def test_matching_gid_plaintext(protected):
    step("rule gid=1001 (inspector) + exe=head → plaintext | run as inspector")
    acl_add(ACL_ID, 100, "*", 1001, HEAD, "r", "plaintext")
    view, text = protected
    result = run(HEAD, view, *INSPECTOR)
    assert result.returncode == 0
    assert text.encode() in result.stdout


def test_matching_gid_ciphertext(protected):
    step("rule gid=1001 (inspector) + exe=cat → ciphertext | run as inspector")
    acl_add(ACL_ID, 100, "*", 1001, CAT, "r", "ciphertext")
    view, text = protected
    result = run(CAT, view, *INSPECTOR)
    assert result.returncode == 0
    assert text.encode() not in result.stdout


def test_wrong_gid_denied(protected):
    step("rule gid=1001 (inspector) | run as pi (gid=1000) → gid mismatch → expect EACCES")
    acl_add(ACL_ID, 100, "*", 1001, HEAD, "r", "plaintext")
    view, _ = protected
    assert run(HEAD, view, *PI).returncode != 0
