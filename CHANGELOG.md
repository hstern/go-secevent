# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `SubjectAs[T]` and `SET.IssSub` now match the value form of the `sub_id`
  Subject Identifier only. go-subjectid v0.2.0 made the value form the single
  dynamic type `Parse` returns and a Go-built `SET` should hold, so the
  reflection-based pointer-form fallback the accessors carried is unreachable
  through any supported flow; it is removed along with its `reflect` import. A
  `SET` hand-built with a `*subjectid.IssSubID` Subject now reports `ok=false`
  from these accessors instead of being dereferenced. Consumers reading subjects
  produced by `Parse`, or building SETs with value-form subjects, are unaffected.

## [0.2.0] - 2026-06-21

### Changed

- **Breaking:** Upgraded [`go-subjectid`](https://github.com/hstern/go-subjectid)
  to v0.2.0, whose `Parse` now returns Subject Identifiers in their value form
  (for example `subjectid.IssSubID`) rather than the pointer form. A parsed
  `SET` now holds the same value form a `SET` built in Go holds, so a type
  switch on `SET.Subject` no longer has to special-case the parsed shape — but
  code that asserted the parsed subject as `*subjectid.IssSubID` must now assert
  the value form. The `SubjectAs[T]` and `SET.IssSub` accessors are unchanged:
  they still return the value form and still absorb a hand-built pointer-form
  subject, so consumers already using them need no changes. The `SET.Subject`
  documentation now describes the value form as the parsed type.

## [0.1.1] - 2026-06-21

### Added

- `SubjectAs[T]` and `SET.IssSub` accessors that read the typed `sub_id`
  Subject Identifier of a `SET` without handling a value-vs-pointer
  distinction by hand. A parsed `SET` holds the pointer form of its identifier
  (because [`go-subjectid`](https://github.com/hstern/go-subjectid)'s registry
  constructors return pointers), whereas a `SET` built in Go holds the value
  form; both accessors return the value form either way. The `SET.Subject`
  field documentation now states the parsed dynamic type.

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

[Unreleased]: https://github.com/hstern/go-secevent/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hstern/go-secevent/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/hstern/go-secevent/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hstern/go-secevent/releases/tag/v0.1.0
