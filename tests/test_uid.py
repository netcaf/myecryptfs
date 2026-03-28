"""
test_uid.py — UID-based ACL rules.

Verifies that rules matching on a specific uid (inspector=1001)
allow that user through and deny everyone else.
"""

import pytest
from helpers import step, run, acl_add, acl_clear, HEAD, CAT, PI, INSPECTOR

ACL_ID = 2


@pytest.fixture
def protected(make_file):
    return make_file(acl_id=ACL_ID)


@pytest.fixture(autouse=True)
def clean():
    acl_clear(ACL_ID)
    yield
    acl_clear(ACL_ID)


def test_matching_uid_plaintext(protected):
    step("rule uid=1001 (inspector) + exe=head → plaintext | run as inspector")
    acl_add(ACL_ID, 100, 1001, "*", HEAD, "r", "plaintext")
    view, text = protected
    result = run(HEAD, view, *INSPECTOR)
    assert result.returncode == 0
    assert text.encode() in result.stdout


def test_matching_uid_ciphertext(protected):
    step("rule uid=1001 (inspector) + exe=cat → ciphertext | run as inspector")
    acl_add(ACL_ID, 100, 1001, "*", CAT, "r", "ciphertext")
    view, text = protected
    result = run(CAT, view, *INSPECTOR)
    assert result.returncode == 0
    assert text.encode() not in result.stdout


def test_wrong_uid_denied(protected):
    step("rule uid=1001 (inspector) | run as pi (uid=1000) → uid mismatch → expect EACCES")
    acl_add(ACL_ID, 100, 1001, "*", HEAD, "r", "plaintext")
    view, _ = protected
    assert run(HEAD, view, *PI).returncode != 0


def test_wildcard_uid_any_user(protected):
    step("rule uid=* (wildcard) | run as pi → any uid allowed → expect plaintext")
    acl_add(ACL_ID, 100, "*", "*", HEAD, "r", "plaintext")
    view, text = protected
    result = run(HEAD, view, *PI)
    assert result.returncode == 0
    assert text.encode() in result.stdout
