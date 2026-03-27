"""
test_rules.py — debugfs rule management (add / clear / list).
No test files needed — only exercises the control interface.
"""

import pytest
from helpers import step, acl_add, acl_clear, acl_write, rules_dump, CAT, HEAD

ACL_ID = 9


@pytest.fixture(autouse=True)
def clean():
    acl_clear(ACL_ID)
    yield
    acl_clear(ACL_ID)


def test_rule_appears_after_add():
    step("add one rule → expect it visible in rules dump")
    acl_add(ACL_ID, 100, "*", "*", CAT, "r", "ciphertext")
    assert "content=ciphertext" in rules_dump()


def test_rules_cleared():
    step("add rule then clear → expect rule count = 0")
    acl_add(ACL_ID, 100, "*", "*", CAT, "r", "ciphertext")
    acl_clear(ACL_ID)
    assert f"acl_id={ACL_ID} (0 rules)" in rules_dump()


def test_two_rules_listed():
    step("add two rules → expect both visible and count = 2")
    acl_add(ACL_ID, 100, "*", "*", CAT,  "r", "ciphertext")
    acl_add(ACL_ID,  50, "*", "*", HEAD, "r", "plaintext")
    dump = rules_dump()
    assert f"acl_id={ACL_ID} (2 rules)" in dump
    assert "content=ciphertext" in dump
    assert "content=plaintext"  in dump


def test_invalid_command_rejected():
    step("write unknown command to control file → expect kernel to return EINVAL")
    with pytest.raises(OSError):
        acl_write("invalid_cmd 99\n")
