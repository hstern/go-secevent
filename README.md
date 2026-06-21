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
authorization or authentication assertion (RFC 8417 §4). `Validate` checks
only that the required claims are present; a validated SET carries no "still
good for auth" semantics.

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

## Install

```bash
go get github.com/hstern/go-secevent
```

## Quickstart

### Parse and inspect typed events

`Parse` takes the already-verified, already-base64url-decoded claims-set
bytes (a JOSE/transport layer produces them) and decodes liberally. `Validate`
checks the §2.2 required-claim MUSTs. `Events.Typed` decodes a known event
through the registry; an event type this build has not imported stays raw and
round-trips byte-for-byte.

```go
payload := []byte(`{
    "iss": "https://idp.example.com/",
    "iat": 1615305600,
    "jti": "set-0001",
    "aud": "https://receiver.example.com/",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
            "event_timestamp": 1615305500
        }
    }
}`)

set, err := secevent.Parse(payload)
if err != nil {
    return err
}
if err := set.Validate(); err != nil {
    return err // e.g. errors.Is(err, secevent.ErrNoEvents)
}

for uri := range set.Events.Raw() {
    event, ok, err := set.Events.Typed(uri)
    switch {
    case err != nil:
        // a registered decoder rejected the payload
    case ok:
        // event is the typed value for a registered vocabulary
        _ = event.EventTypeURI()
    default:
        // no decoder registered: the payload stays raw at set.Events.Raw()[uri]
    }
}
```

### Build and encode a SET

`Encode` is the strict half of the library's "liberal unmarshal, strict
marshal" contract: it calls `Validate` first and refuses to emit a SET that
is missing a required claim. It does not sign — it emits the claims-set bytes
a signer wraps in a JWS.

```go
subject, err := subjectid.Parse([]byte(
    `{"format":"iss_sub","iss":"https://idp.example.com/","sub":"user-7f3e2a"}`,
))
if err != nil {
    return err
}

set := &secevent.SET{
    Issuer:   "https://idp.example.com/",
    IssuedAt: time.Unix(1615305600, 0),
    JWTID:    "set-0002",
    Audience: secevent.Audience{"https://receiver.example.com/"},
    Subject:  subject,
    Events: secevent.Events{
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked": json.RawMessage(`{"initiating_entity":"policy"}`),
    },
}

payload, err := set.Encode()
if err != nil {
    return err // a required claim was unset
}
// payload is the compact JSON claims set, ready for a JOSE signer.
```

Subject Identifiers come from
[`go-subjectid`](https://github.com/hstern/go-subjectid): the `sub_id` claim
is held as a `subjectid.SubjectIdentifier`, parsed and validated there.

### Register an event type

An event vocabulary (such as OpenID CAEP or RISC) implements the `Event`
interface for its payload and registers a decoder for its event-type URI.
`RegisterEventType` is the only registration call — place it in the vocabulary
package's `init` function (`init` is *where* you register, not an alternative
to registering) so a single side-effect import wires the whole vocabulary in,
the same idiom as `database/sql` drivers. Registration is process-wide and
permanent.

```go
const sessionRevokedURI = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

type SessionRevoked struct {
    InitiatingEntity string `json:"initiating_entity"`
}

func (SessionRevoked) EventTypeURI() string { return sessionRevokedURI }

func init() {
    secevent.RegisterEventType(sessionRevokedURI, func(raw json.RawMessage) (secevent.Event, error) {
        var e SessionRevoked
        if err := json.Unmarshal(raw, &e); err != nil {
            return nil, err
        }
        return e, nil
    })
}

// Once registered, Events.Typed decodes the member into the concrete type:
//
//   event, ok, err := set.Events.Typed(sessionRevokedURI)
//   if ok {
//       revoked := event.(SessionRevoked)
//       _ = revoked.InitiatingEntity
//   }
```

See the [package examples](https://pkg.go.dev/github.com/hstern/go-secevent#pkg-examples)
for runnable versions of each flow.

## Status

**`v0.1.0`** — the first tagged release. As a `v0.x` series, the public API may
still change per [SemVer](https://semver.org/) before `v1.0.0`. Runtime
dependencies: the standard library plus `go-subjectid`.

## License

[Apache-2.0](LICENSE).
