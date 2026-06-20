# go-secevent

a typed codec and event-type registry for RFC 8417 Security Event Tokens.

Implements **RFC 8417 — Security Event Token (SET)** (Proposed Standard,
2018-07). Spec: <https://www.rfc-editor.org/rfc/rfc8417.html>

## What this library is and is not

It is a claim-set codec for the SET envelope — typed Go structs for the
RFC 8417 §2.2 claims (`iss`, `iat`, `jti`, `aud`, `sub_id`, `txn`, `toe`,
and the required `events` object), a stdlib (`encoding/json`) parser and
encoder, validation of the §2.2/§2.3 claim MUSTs, and an **event-type
registry** through which event vocabularies plug in typed decoders.

A SET is a JWT whose payload states that a *security event occurred*. This
library owns only the claims set: it receives the already-verified, decoded
claims-set bytes, parses them into a typed `SET`, and encodes them back.

**A SET is not an access token** and must never be treated as an
authorization or authentication assertion (RFC 8417 §4).

It is not a JWT/JOSE stack. The following are deliberately out of scope and
belong in dedicated libraries:

- **JWS signature verification / signing** and the compact-serialization
  framing — verify the JWS with a JOSE/transport layer and hand the decoded
  claims-set bytes to this library.
- **Concrete event payloads** — event vocabularies such as OpenID CAEP and
  RISC define their event types and register typed decoders through this
  library's registry; this library ships none itself.
- **Delivery, streams, and endpoints** — a Shared Signals transport's job.

Subject Identifiers (`sub_id`, RFC 9493) are handled by
[`go-subjectid`](https://github.com/hstern/go-subjectid).

## Status

**Pre-release (`v0.x`).** Under active development toward `v0.1.0`; the public
API may change within the `v0.x` series per [SemVer](https://semver.org/).
Runtime dependencies: the standard library plus `go-subjectid`.

## Install

```bash
go get github.com/hstern/go-secevent
```

## License

[Apache-2.0](LICENSE).
