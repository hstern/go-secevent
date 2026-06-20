# AGENTS.md — go-secevent

Go library implementing RFC 8417 — Security Event Token (SET).

## Dependencies

- **Runtime: standard library plus the Subject Identifier sibling.**
  The only non-stdlib runtime dependency is
  [`github.com/hstern/go-subjectid`](https://github.com/hstern/go-subjectid)
  (RFC 9493), used for the `sub_id` claim. Any *other* runtime
  dependency needs a discussion and a justification in the PR
  description; the default answer is "no" — this library is a
  claims-set codec and should not grow a JOSE, HTTP, or crypto
  dependency (those concerns live in sibling libraries).
- **Tests: standard library only by default.** Test-only deps still
  need a one-line justification.
- **Build-time tooling: unconstrained.** Generators, linters, and
  release tooling are invoked via `go run` with a pinned version (see
  the CI `lint` job) or live under `tools/` (separate `go.mod`); they
  never end up in library users' `go.sum`.
- **`go.mod`**: keep the `module` path stable at
  `github.com/hstern/go-secevent` (no `/vN` suffix for v0.x/v1.x — Go
  SemVer rule). Major-version bumps follow the `go-jose` branch
  pattern.

## What this library is (and is not)

A typed codec for the RFC 8417 SET *claims set* and its registry of
event types. It parses verified claims-set bytes into a `SET`,
validates the §2.2/§2.3 claim MUSTs, and encodes a `SET` back to bytes.

Deliberately out of scope, in dedicated libraries:

- **JWS sign/verify and the compact-serialization framing** — a
  JOSE/transport layer hands this library the decoded claims-set bytes.
- **Concrete event payloads** — event vocabularies (CAEP, RISC) define
  and register their own event types through this library's registry.
- **Delivery, streams, and endpoints** — a transport layer's concern.

## Conventions

- Every `.go` file starts with the two-line copyright + SPDX header
  (see any existing source file).
- Lenient unmarshal, strict marshal: `Parse` tolerates anything
  well-formed; `Encode`/`Validate` enforce the required-claim MUSTs.
- Open fields (`events` payloads) are `json.RawMessage` for byte-stable
  round-trips — never `map[string]any`.
- A SET is **not** an access token (RFC 8417 §4); `Validate` checks
  structure only and must never imply authorization.
