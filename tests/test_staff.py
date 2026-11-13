"""Tests for the staff membership primitives (groups + allowlist)."""

from __future__ import annotations

import json

from ccdb_mcp.staff import StaffEvaluator, StaffList


def test_groups_membership():
    ev = StaffEvaluator(staff_groups=("cc-staff", "scinet"))
    assert ev.enabled
    assert ev.is_staff("alice", ["cc-staff"])
    assert ev.is_staff("alice", ["SomeRole", "scinet"])
    assert not ev.is_staff("bob", ["ras"])
    assert not ev.is_staff("bob", [])


def test_groups_case_and_prefix_sensitive():
    ev = StaffEvaluator(staff_groups=("cc-staff",))
    assert not ev.is_staff("alice", ["CC-Staff"])
    assert not ev.is_staff("alice", ["evil-cc-staff"])


def test_no_groups_configured_means_no_one():
    ev = StaffEvaluator(staff_groups=())
    assert not ev.enabled
    assert not ev.is_staff("alice", ["cc-staff"])


def test_allowlist_only(tmp_path):
    store = tmp_path / "staff.json"
    store.write_text(json.dumps({"staffUsernames": ["alice"]}))
    ev = StaffEvaluator(staff_groups=(), staff_list_path=str(store))
    try:
        assert ev.is_staff("alice", []) is True
        assert ev.is_staff("bob", []) is False
    finally:
        ev.close()


def test_allowlist_and_groups_compose(tmp_path):
    store = tmp_path / "staff.json"
    store.write_text(json.dumps({"staffUsernames": ["alice"]}))
    ev = StaffEvaluator(staff_groups=("scinet",), staff_list_path=str(store))
    try:
        assert ev.is_staff("alice", []) is True          # allowlist
        assert ev.is_staff("bob", ["scinet"]) is True    # group
        assert ev.is_staff("bob", []) is False
    finally:
        ev.close()


def test_staff_list_reloads(tmp_path):
    store = tmp_path / "staff.json"
    store.write_text(json.dumps({"staffUsernames": ["alice"]}))
    rl = StaffList(store, reload_seconds=0.01)
    try:
        assert "alice" in rl.usernames()
        store.write_text(json.dumps({"staffUsernames": ["alice", "bob"]}))
        import os
        os.utime(store)
        for _ in range(50):
            if "bob" in rl.usernames():
                break
            import time
            time.sleep(0.01)
        assert "bob" in rl.usernames()
    finally:
        rl.close()


def test_staff_list_missing_file_empty(tmp_path):
    rl = StaffList(tmp_path / "nope.json")
    assert rl.usernames() == frozenset()
    rl.close()
