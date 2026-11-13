"""Pin the CCDB payload quirks that are real and must not be "fixed".

The fixture is a scrubbed reconstruction of the review payload T10: storage
allocations with empty dates, compute/GPU allocations with real windows, a
non-contiguous alloc_id range with a missing 009, a 12-member roster spanning
five institutions that appears on both of the person's RAPs, and nested role
objects.  Names, emails, usernames and identifiers are synthetic.

These tests are intentionally explicit about the odd shapes.  A future
"cleanup" that renames ``primary_role_deactivated?``, grows a top-level
``role``, asserts contiguous ``alloc_id``s, assumes a single-institution
roster, or invents a fixed allocation schema will fail here first.
"""

from __future__ import annotations

import json
from pathlib import Path

from ccdb_mcp.schemas import CcdbAllocation, CcdbPerson, CcdbPersonWithRaps, CcdbRap

FIXTURE = Path(__file__).parent / "fixtures" / "person_t10_scrubbed.json"


def _payload() -> dict:
    return json.loads(FIXTURE.read_text())


# ----------------------------------------------------------------------
# Whole-record validation
# ----------------------------------------------------------------------

def test_fixture_validates_as_person_with_raps():
    person = CcdbPersonWithRaps.model_validate(_payload())

    assert person.username == "tess.example"
    assert person.primary_role_deactivated is False
    assert [rap.rapi for rap in person.raps] == ["ssu-900-aa", "ssu-900-af"]
    assert [rap.groupname for rap in person.raps] == [
        "def-example", "rrg-example-ad"]
    assert len(person.raps[0].allocations) == 8
    assert len(person.raps[0].members) == 12
    assert len(person.raps[1].members) == 12


# ----------------------------------------------------------------------
# primary_role_deactivated? keeps its literal question mark
# ----------------------------------------------------------------------

def test_primary_role_deactivated_key_keeps_literal_question_mark():
    raw = _payload()

    assert "primary_role_deactivated?" in raw
    assert raw["primary_role_deactivated?"] is False

    schema = CcdbPersonWithRaps.model_json_schema()
    assert "primary_role_deactivated?" in schema["properties"]
    assert "primary_role_deactivated" not in schema["properties"]

    # The Python-side field reads through the alias.
    person = CcdbPersonWithRaps.model_validate(raw)
    assert person.primary_role_deactivated is False
    assert person.model_dump(by_alias=True)["primary_role_deactivated?"] is False


def test_nested_deactivated_key_also_keeps_literal_question_mark():
    raw = _payload()
    role = raw["raps"][0]["owner"]["person"]["role"]

    assert "deactivated?" in role

    schema = CcdbRap.model_json_schema()
    role_schema = schema["$defs"]["CcdbRole"]
    assert "deactivated?" in role_schema["properties"]
    assert "deactivated" not in role_schema["properties"]


# ----------------------------------------------------------------------
# Role asymmetry: top-level person has no role, nested persons do
# ----------------------------------------------------------------------

def test_role_exists_only_on_nested_owner_and_members():
    raw = _payload()

    assert "role" not in raw

    owner_role = raw["raps"][0]["owner"]["person"]["role"]
    assert owner_role["institution"] == "University of Toronto"

    member_roles = [m["person"]["role"] for m in raw["raps"][0]["members"]]
    assert all(role is not None for role in member_roles)
    assert len(member_roles) == 12

    person = CcdbPersonWithRaps.model_validate(raw)
    assert person.role is None
    assert person.raps[0].owner.person.role is not None
    assert all(member.person.role is not None for member in person.raps[0].members)


def test_top_level_base_model_has_no_role_in_fixture():
    # CcdbPerson declares role because nested persons carry it; the top-level
    # payload simply omits it.  Both must validate.
    raw = _payload()
    assert "role" not in raw
    assert CcdbPerson.model_validate(raw).role is None


# ----------------------------------------------------------------------
# Date fields: storage rows use "", compute/GPU rows use a dated string
# ----------------------------------------------------------------------

def test_dates_allow_empty_string_and_dated_string_side_by_side():
    storage = {
        a["alloc_id"]: a for a in _payload()["raps"][0]["allocations"]
    }
    dated = {
        a["alloc_id"]: a for a in _payload()["raps"][1]["allocations"]
    }

    assert all(a["start_date"] == "" and a["expire_date"] == ""
               for a in storage.values())
    assert dated["ssu-900-af-001"]["start_date"] == (
        "2026-04-07 00:00:00 -0400"
    )
    assert dated["ssu-900-af-001"]["expire_date"] == (
        "2027-04-01 00:00:00 -0400"
    )

    person = CcdbPersonWithRaps.model_validate(_payload())
    dates = {
        a.alloc_id: (a.start_date, a.expire_date)
        for a in person.raps[0].allocations
    }
    assert dates["ssu-900-aa-005"] == ("", "")
    assert person.raps[1].allocations[0].start_date == (
        "2026-04-07 00:00:00 -0400"
    )


# ----------------------------------------------------------------------
# alloc_id sequences are not contiguous
# ----------------------------------------------------------------------

def test_alloc_ids_are_non_contiguous_by_design():
    raw_ids = [a["alloc_id"] for a in _payload()["raps"][0]["allocations"]]

    assert raw_ids == [
        "ssu-900-aa-005",
        "ssu-900-aa-006",
        "ssu-900-aa-007",
        "ssu-900-aa-008",
        "ssu-900-aa-010",
        "ssu-900-aa-011",
        "ssu-900-aa-012",
        "ssu-900-aa-013",
    ]
    # 009 is absent and 001-004 were filtered upstream.  Never assert
    # contiguity or assign a meaning to the gap.
    assert "ssu-900-aa-009" not in raw_ids
    assert not {"ssu-900-aa-001", "ssu-900-aa-002",
                "ssu-900-aa-003", "ssu-900-aa-004"} & set(raw_ids)

    person = CcdbPersonWithRaps.model_validate(_payload())
    model_ids = [a.alloc_id for a in person.raps[0].allocations]
    assert model_ids == raw_ids


# ----------------------------------------------------------------------
# Roster spans several institutions and can repeat on another RAP
# ----------------------------------------------------------------------

def test_roster_spans_five_institutions_not_just_the_owner():
    rap = _payload()["raps"][0]

    owner_institution = rap["owner"]["person"]["role"]["institution"]
    member_institutions = {
        member["person"]["role"]["institution"] for member in rap["members"]
    }

    assert owner_institution == "University of Toronto"
    assert len(rap["members"]) == 12
    assert len(member_institutions) == 5
    assert member_institutions == {
        "University of Toronto",
        "McMaster University",
        "University of Waterloo",
        "Queen's University",
        "University of British Columbia",
    }
    assert any(inst != owner_institution for inst in member_institutions)


def test_the_same_roster_appears_on_both_raps():
    first, second = _payload()["raps"]

    first_members = [m["person"]["cci"] for m in first["members"]]
    second_members = [m["person"]["cci"] for m in second["members"]]

    assert first_members == second_members
    assert len(set(first_members)) == 12


# ----------------------------------------------------------------------
# The RAP tool returns an unwrapped RAP object
# ----------------------------------------------------------------------

def test_rap_tool_shape_is_unwrapped_and_has_no_top_level_identity():
    rap = CcdbRap.model_validate(_payload()["raps"][1])

    # No top-level identity: ownership is only readable through owner.person.
    assert "cci" not in _payload()["raps"][1]
    assert "username" not in _payload()["raps"][1]
    assert rap.rapi == "ssu-900-af"
    assert rap.groupname == "rrg-example-ad"
    assert rap.title == "Computational studies of example membranes"
    assert rap.owner.person.username == "tess.example"


# ----------------------------------------------------------------------
# Allocation keys depend on the resource family
# ----------------------------------------------------------------------

def test_allocation_keys_are_resource_family_specific():
    rap = CcdbRap.model_validate(_payload()["raps"][1])
    compute, gpu = rap.allocations

    assert compute.resource == "trillium-cpu"
    assert compute.core_years == 100000.0
    assert compute.core_equivalent == 120000.0
    assert compute.gpu_rgu_years is None

    assert gpu.resource == "trillium-gpu"
    assert gpu.gpu_rgu_years == 5000.0
    assert gpu.gpu_rgu_equivalent_years == 6000.0
    assert gpu.core_years is None

    storage = CcdbRap.model_validate(_payload()["raps"][0]).allocations
    assert any(a.project_storage_tb for a in storage)
    assert any(a.nearline_storage_tb for a in storage)

    # There is no fixed allocation schema; extra family keys are preserved.
    schema = CcdbAllocation.model_json_schema()
    for key in ("core_years", "gpu_rgu_years", "project_storage_tb",
                "nearline_storage_tb"):
        assert key in schema["properties"]
    assert schema.get("additionalProperties") is True

    with_unknown = CcdbAllocation.model_validate(
        {"alloc_id": "x-001", "resource": "future", "mystery_units": 7}
    )
    assert with_unknown.model_dump()["mystery_units"] == 7


# ----------------------------------------------------------------------
# Structured success/failure envelope
# ----------------------------------------------------------------------

def test_error_envelope_validates_for_both_tools():
    for model in (CcdbPersonWithRaps, CcdbRap):
        payload = model.model_validate({
            "ok": False,
            "code": "not_found",
            "error": "No CCDB allocation record available for nobody",
        })
        assert payload.ok is False
        assert payload.code == "not_found"
        assert payload.error

        schema = model.model_json_schema()
        for key in ("ok", "code", "error"):
            assert key in schema["properties"]


def test_success_marker_validates_alongside_real_payload():
    person = CcdbPersonWithRaps.model_validate({**_payload(), "ok": True})
    assert person.ok is True
    assert person.code is None

    rap_payload = _payload()["raps"][0]
    rap = CcdbRap.model_validate({**rap_payload, "ok": True})
    assert rap.ok is True
    assert rap.rapi == "ssu-900-aa"
    assert rap.groupname == "def-example"
