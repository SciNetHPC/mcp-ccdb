# Contributing

Thanks for your interest. This project is maintained by SciNet HPC Consortium
and is used in production, so changes are reviewed conservatively.

## Start with an issue

Open an issue before writing code. Describe the problem, the deployment it
affects, and what you propose. That avoids a large pull request that cannot be
merged for policy or compatibility reasons.

## Pull requests

Pull requests are welcome and are reviewed by the maintainers. Merge rights
stay with SciNet; being a consumer of the software does not imply write
access. The maintainers decide whether, when, and in what form a change lands.

A pull request should:

- be focused on one problem,
- include tests for behaviour changes,
- keep `pytest` green,
- preserve the configuration surface unless the change is discussed first —
  other deployments pin a release and rely on it,
- avoid site-specific values. Hostnames, group names, and API keys belong in
  configuration, not in code.

## Development

```sh
uv sync --extra test
uv run --no-sync pytest -q
```

Python 3.11 or newer is required. The tests stub the upstream API and use
local OIDC fixtures; they need no network access.

## CCDB quirks

`src/ccdb_mcp/schemas.py` deliberately models several oddities of the upstream
payloads, and `tests/test_schema_quirks.py` pins them. If a change makes one of
those tests fail, decide whether the upstream shape actually changed. Do not
silently normalise a documented quirk: other clients may depend on the key
names and value shapes.

## Commit messages

Use the imperative mood and a short subject line, for example:

```
Reject a RAP id that is not one of the caller's own
```

Explain the reason in the body when it is not obvious. Reference the issue if
there is one.

## Secrets

Never commit credentials, tokens, private keys, or a populated `.env`. The
repository is scanned for secrets in CI, and GitHub push protection should be
enabled on the repository. If you find a committed secret, report it privately
as described in [SECURITY.md](SECURITY.md) rather than opening an issue.

## Licence of contributions

By submitting a pull request you agree that your contribution is licensed
under the MIT licence used by this project (inbound = outbound). Do not submit
code you cannot license that way.
