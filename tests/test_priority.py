"""
test_priority.py — Priority ordering between rules (SRS §6.2).

When two rules match the same subject, the higher-priority rule wins.
"""

import pytest
from helpers import step, run, acl_add, acl_clear, HEAD, INSPECTOR

ACL_ID = 5


@pytest.fixture
def protected(make_file):
    return make_file(acl_id=ACL_ID)


@pytest.fixture(autouse=True)
def clean():
    acl_clear(ACL_ID)
    yield
    acl_clear(ACL_ID)


def test_high_priority_ciphertext_wins(protected):
    step("prio=100 ciphertext vs prio=50 plaintext | same exe → higher prio wins → expect ciphertext")
    acl_add(ACL_ID, 100, "*", "*", HEAD, "r", "ciphertext")
    acl_add(ACL_ID,  50, "*", "*", HEAD, "r", "plaintext")
    view, text = protected
    result = run(HEAD, view, *INSPECTOR)
    assert result.returncode == 0
    assert text.encode() not in result.stdout


def test_high_priority_plaintext_wins(protected):
    step("prio=100 plaintext vs prio=50 ciphertext | same exe → higher prio wins → expect plaintext")
    acl_add(ACL_ID, 100, "*", "*", HEAD, "r", "plaintext")
    acl_add(ACL_ID,  50, "*", "*", HEAD, "r", "ciphertext")
    view, text = protected
    result = run(HEAD, view, *INSPECTOR)
    assert result.returncode == 0
    assert text.encode() in result.stdout
