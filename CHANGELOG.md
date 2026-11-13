# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) for the release tag.

## [0.3.5] - 2026-11-13

First public release. This is the source of the `0.3.5` image; the release
that was running in SciNet production at the time of publication is `0.3.4`
and predates the fixes below.

### Added

- Declared output schemas for both tools, including a structured failure
  envelope (`ok`, `code`, `error`) so a typed client can branch on the failure
  class without parsing prose.
- A synthetic CCDB fixture and tests that pin the upstream payload quirks:
  `?`-suffixed keys, empty-string dates on storage allocations, non-contiguous
  `alloc_id` sequences, resource-family-specific allocation keys, and rosters
  that span institutions.
- RAP alias handling: the RAP id, group name, and allocation ids are accepted
  case-insensitively, and a sub-allocation id resolves to its parent RAP.
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE` (MIT), and this
  changelog.
- CI workflows that run the tests and scan history for secrets.

### Changed

- The username tool trims its input, rejects empty or whitespace-only input
  with `invalid_argument`, and refuses a cross-user lookup by a non-staff
  caller before calling the upstream API.
- Non-staff callers may look up only RAPs they are members of, checked against
  their own CCDB record; staff may look up any RAP.
- Allocation shapes are typed by resource family, while unknown keys are
  preserved rather than dropped.
- Deployment manifests and the site-specific runbook were left out; this
  repository contains service code only.

### Fixed

- The username tool returned a shape that did not match its declared output
  schema, so the MCP SDK rejected the response.
- A malformed or unsupported input could reach the upstream API instead of
  being rejected locally.

[0.3.5]: https://github.com/SciNetHPC/mcp-ccdb/releases/tag/v0.3.5
