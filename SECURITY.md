# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting on this repository
(**Security → Advisories → Report a vulnerability**). If that is unavailable,
contact the SciNet HPC Consortium maintainers through
<https://www.scinethpc.ca/> and ask for the security contact.

Include:

- the affected version or commit,
- what an attacker can do and what they need to start,
- a reproduction or a precise description of the path,
- any suggested fix.

We will acknowledge receipt, investigate, and coordinate disclosure with you.
Please give us a reasonable window before publishing details.

## Supported versions

Only the latest tagged release is supported. There are no long-term support
branches. Fixes are issued as a new tag; deployments are expected to pin a tag
and upgrade deliberately.

## Scope

In scope:

- access to another user's CCDB record or RAP as a non-staff caller,
- authentication bypass, including accepting an ID token as an access token,
- token forgery, or acceptance of an fmcpv1 token minted for another service,
- revocation or blacklist bypass,
- staff escalation through a group claim, a tool argument, or a writable file,
- secret disclosure through logs or error responses,
- Server-Side Request Forgery through the configured backend URL.

Out of scope:

- findings that require control of the OIDC provider, the backend API, or the
  container platform,
- denial of service through unbounded traffic (put a proxy in front),
- the accuracy or completeness of CCDB data itself; report that to the
  database's operators.

## Known design properties

These are intentional, not vulnerabilities:

- **`tools/list` is anonymous.** A client may discover the tool names and
  schemas without a credential. Invoking either tool still requires a valid
  token, and the identity used for the lookup comes from that token.
- **Non-staff callers are scoped to their own records.** Cross-user access is
  refused before the backend is called.
- **A malformed fmcpv1 token is rejected, not retried as OIDC.** The `fmcpv1.`
  marker is authoritative for how a token must be handled.
- **Backend failures are reported as `not_found`.** The tool cannot tell a
  missing record from an upstream error without leaking backend detail.
- **The staff list is a file on a shared volume.** Anyone who can write it can
  grant cross-user access; protect the volume accordingly.
- **The DNS-rebinding guard fails closed.** With the default `ALLOWED_HOSTS`,
  a deployment that does not set its public hostname is unusable rather than
  unprotected.
