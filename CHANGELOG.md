# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-21

### Added

- Typed `SET` envelope for the RFC 8417 §2.2 claims set — `iss`, `iat`, `jti`,
  `aud`, `sub_id`, `txn`, `toe`, and the required `events` object — with the
  `NumericDate` (RFC 7519 seconds-since-epoch) and string-or-array `Audience`
  wire types. The `sub_id` Subject Identifier is held as a
  `subjectid.SubjectIdentifier` via
  [`go-subjectid`](https://github.com/hstern/go-subjectid) (RFC 9493).
- Raw `Events` container over `map[string]json.RawMessage`, preserving each
  event payload's bytes so an unrecognized event-type URI round-trips
  byte-for-byte (`Raw`, `Len`).
- `Parse` (liberal decode of already-verified, already-base64url-decoded
  claims-set bytes; no JOSE), `SET.Validate` (the §2.2 required-claim MUSTs —
  `iss`/`iat`/`jti` present and `events` non-empty — as joined typed
  `*ValidationError`s wrapping `errors.Is`-matchable sentinels), and
  `SET.Encode` (strict required-claim check at the marshal boundary; emits the
  claims-set bytes a signer wraps in a JWS, without signing).
- Event-type registry — the `Event` interface, `RegisterEventType` /
  `LookupEventType`, and `Events.Typed` — through which event vocabularies
  (such as OpenID CAEP and RISC) plug in typed decoders while unknown event
  types stay raw.

[Unreleased]: https://github.com/hstern/go-secevent/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hstern/go-secevent/releases/tag/v0.1.0
