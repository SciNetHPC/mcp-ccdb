"""Identifier handling shared by the two CCDB tools.

RAP ids are lowercase by construction, but callers paste them from job
scripts and papers.  Matching is deliberately case-insensitive and
whitespace-trimmed, and membership accepts the same aliases (RAP id, group
name, alloc_id) that the upstream API accepts.
"""

from __future__ import annotations

from ccdb_mcp.server import _rap_aliases, _rap_root


def test_rap_root_trims_and_casefolds():
    assert _rap_root("  JIZ-261-AA  ") == "jiz-261-aa"
    assert _rap_root("JIZ-261-AA") == _rap_root("jiz-261-aa")


def test_rap_root_strips_a_numeric_sub_allocation_suffix():
    assert _rap_root("rrg-2030-00000-01") == "rrg-2030-00000"
    assert _rap_root("SSU-900-AA-005") == "ssu-900-aa"
    # A RAP id whose last part is numeric is not a sub-allocation.
    assert _rap_root("rrg-2030-00000") == "rrg-2030-00000"


def test_rap_aliases_cover_rap_id_group_name_and_alloc_ids():
    aliases = _rap_aliases({
        "rapi": "RRG-2030-00001",
        "groupname": "RRG-ALICE",
        "allocations": [{"alloc_id": "DEF-EXAMPLE-005"}],
    })

    assert "rrg-2030-00001" in aliases
    assert "rrg-alice" in aliases
    assert "def-example-005" in aliases


def test_rap_aliases_handle_missing_fields():
    assert _rap_aliases({}) == set()
    assert _rap_aliases({"rapi": None, "allocations": None}) == set()
