"""
test_combined.py — AND logic: uid + gid + executable must all match.

A rule only fires when every specified subject condition is satisfied.
Failing any one condition → no match → DENY.
"""

import pytest
from helpers import step, run, acl_add, acl_clear, HEAD, CAT, PI, INSPECTOR

ACL_ID = 4


@pytest.fixture
def protected(make_file):
    return make_file(acl_id=ACL_ID)


@pytest.fixture(autouse=True)
def clean():
    acl_clear(ACL_ID)
    yield
    acl_clear(ACL_ID)


def test_all_conditions_match_plaintext(protected):
    step("rule uid=1001 + gid=1001 + exe=head → plaintext | all conditions match → expect plaintext")
    acl_add(ACL_ID, 100, 1001, 1001, HEAD, "r", "plaintext")
    view, text = protected
    result = run(HEAD, view, *INSPECTOR)
    assert result.returncode == 0
    assert text.encode() in result.stdout


def test_all_conditions_match_ciphertext(protected):
    step("rule uid=1001 + gid=1001 + exe=cat → ciphertext | all conditions match → expect ciphertext")
    acl_add(ACL_ID, 100, 1001, 1001, CAT, "r", "ciphertext")
    view, text = protected
    result = run(CAT, view, *INSPECTOR)
    assert result.returncode == 0
    assert text.encode() not in result.stdout


def test_wrong_uid_denied(protected):
    step("rule uid=1001 + gid=1001 + exe=head | run as pi (uid=1000) → uid fails AND → expect EACCES")
    acl_add(ACL_ID, 100, 1001, 1001, HEAD, "r", "plaintext")
    view, _ = protected
    assert run(HEAD, view, *PI).returncode != 0


def test_wrong_exe_denied(protected):
    step("rule uid=1001 + gid=1001 + exe=head | run cat as inspector → exe fails AND → expect EACCES")
    acl_add(ACL_ID, 100, 1001, 1001, HEAD, "r", "plaintext")
    view, _ = protected
    assert run(CAT, view, *INSPECTOR).returncode != 0
