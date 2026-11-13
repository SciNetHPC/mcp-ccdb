"""Output schemas for the CCDB MCP tools.

Declared rather than inferred: a tool annotated ``-> ToolResult`` gets no
``outputSchema`` from fastmcp, so without these the servers send
``structuredContent`` that no client can validate against.

Derived from live CCDB responses.  Several CCDB quirks are deliberate and
pinned by ``tests/test_schema_quirks.py``; do not "fix" them silently:

* Several payload keys end in ``?`` (``primary_role_deactivated?``,
  ``deactivated?``).  They are not valid Python identifiers, so the model
  uses aliases; the schema still carries the real key name.
* ``start_date`` and ``expire_date`` come back as empty strings on storage
  allocations, not None.
* The top-level person has no ``role``; the nested ``owner``/``members``
  persons do.
* ``alloc_id`` sequences are not contiguous; skipped ids are expired rows.
* A RAP roster can span several institutions, not just the owner's.
* Allocation keys depend on the resource family; there is no fixed schema.
* The RAP tool returns the RAP unwrapped (no top-level CCI/username); the
  username tool nests RAPs under ``raps``.
* The same roster can appear on more than one of a person's RAPs.

Fields that are optional in the API are optional here, with a default that
the API itself would send, so a payload that omits them still validates.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CcdbAllocation(BaseModel):
    """One resource allocation within a RAP.

    CCDB's allocation keys depend on the resource family; there is no fixed
    allocation schema.  Compute rows carry ``core_years`` and
    ``core_equivalent``, GPU rows ``gpu_rgu_years`` and
    ``gpu_rgu_equivalent_years``, storage rows ``project_storage_tb`` /
    ``project_inodes_millions`` or ``nearline_storage_tb``.  Unknown
    family-specific keys are preserved (``extra="allow"``) rather than
    dropped, so a typed client can read them from structured content.
    """

    model_config = ConfigDict(extra="allow")

    alloc_id: str | None = None
    resource: str | None = None
    # Nullable like the rest: CCDB currently returns "" for storage
    # allocations, but a validating client must not reject a payload if
    # one of these ever comes back as null.
    start_date: str | None = ""
    expire_date: str | None = ""
    core_years: float | None = None
    core_equivalent: float | None = None
    gpu_rgu_years: float | None = None
    gpu_rgu_equivalent_years: float | None = None
    project_storage_tb: int | None = None
    nearline_storage_tb: int | None = None
    project_inodes_millions: float | None = None


class CcdbRole(BaseModel):
    """A person's role at an institution."""

    ccri: str | None = None
    institution: str | None = None
    position: str | None = None
    department: str | None = None
    expired_at: str | None = None
    deactivated: bool = Field(default=None, alias="deactivated?")
    deactivated_at: str | None = None


class CcdbPerson(BaseModel):
    """A person as CCDB represents them."""

    cci: str | None = None
    family_name: str | None = None
    given_name: str | None = None
    username: str | None = None
    primary_email: str | None = None
    language: str | None = None
    active_in_ldap: bool | None = None
    primary_role_deactivated: bool | None = Field(
        default=None, alias="primary_role_deactivated?")
    primary_role_deactivated_at: str | None = None
    role: CcdbRole | None = None


class CcdbRapMember(BaseModel):
    """A RAP participant: the top-level sample carries the person object
    under ``owner`` and ``members``, so the wrapper key is part of the API
    shape."""

    person: CcdbPerson


class CcdbRap(BaseModel):
    """A Resource Allocation Project.

    All fields are optional: on a lookup miss the tool returns a
    schema-conforming object carrying ``ok: false`` and ``error``.
    """

    rapi: str | None = None
    groupname: str | None = None
    title: str | None = None
    allocations: list[CcdbAllocation] = []
    owner: CcdbRapMember | None = None
    members: list[CcdbRapMember] = []
    ok: bool | None = Field(
        default=None,
        description="True on success; False when ``error`` is set",
    )
    code: str | None = Field(
        default=None,
        description="Failure class: invalid_argument, not_found, or forbidden",
    )
    error: str | None = Field(
        default=None,
        description="Non-null when the record was not found, with a message describing why",
    )


class CcdbPersonWithRaps(CcdbPerson):
    """The person object returned by the username endpoint, plus the
    person's RAPs.

    All fields are optional: on a lookup miss the tool returns a
    schema-conforming object carrying ``ok: false`` and ``error``.
    """

    raps: list[CcdbRap] = []
    ok: bool | None = Field(
        default=None,
        description="True on success; False when ``error`` is set",
    )
    code: str | None = Field(
        default=None,
        description="Failure class: invalid_argument, not_found, or forbidden",
    )
    error: str | None = Field(
        default=None,
        description="Non-null when the record was not found, with a message describing why",
    )
