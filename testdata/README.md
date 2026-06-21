# Conformance fixtures

Golden Security Event Token (SET) claims sets used by the round-trip
conformance tests (`conformance_test.go`). Each file is the decoded JWT
claims set — the bytes a JOSE/transport layer hands to `Parse` after it
has verified the JWS and base64url-decoded the payload. None of these
files is a compact JWS; there is no `typ`/`alg`/`kid` framing here.

RFC 8417 ships prose example figures, not machine-readable vectors, so a
spec-derived fixture is transcribed from its figure and a synthetic
fixture is labelled as such below.

| File | Source | Exercises |
|---|---|---|
| `scim_create.json` | RFC 8417 §2.1, transcribed verbatim from the SCIM provisioning example figure | `iss`, `iat`, `jti`, `aud` as a two-member array, a single SCIM `create` event with a non-empty payload |
| `minimal.json` | Synthetic — the smallest SET that satisfies the §2.2 MUSTs | `iss`, `iat`, `jti`, exactly one event whose payload is the empty object `{}` (the event-type URI alone carries meaning, RFC 8417 §2.2) |
| `txn_toe_subid.json` | Synthetic | `aud` as a two-member array, `txn`, `toe` distinct from `iat`, an RFC 9493 `iss_sub` `sub_id`, one event with a non-empty payload |
| `single_aud.json` | Synthetic | `aud` as a bare string (the single-recipient JWT idiom), one event whose payload a registered decoder turns into a typed value |

## Shared Signals interop fixtures (`interop_test.go`)

These fixtures are Shared-Signals-shaped SETs: their `events` are keyed
by the **real public** CAEP 1.0 / RISC event-type URIs under
`https://schemas.openid.net/secevent/…`, carrying representative
payloads. They model the decoded claims-set bytes a Shared Signals
receiver hands to `Parse`, and drive the consumer flow end to end — Parse
→ Validate → decode the recognized event types through the registry →
leave the rest raw and byte-stable. The library defines no CAEP/RISC
payload types itself (those are downstream event vocabularies); the
interop tests register test-local decoders standing in for them.

| File | Source | Exercises |
|---|---|---|
| `caep_session_revoked.json` | Synthetic, CAEP `session-revoked` shape | bare-string `aud`, a top-level `iss_sub` `sub_id` a receiver keys revocation by, one CAEP event decoded to a typed value through the registry |
| `risc_account_disabled.json` | Synthetic, RISC `account-disabled` shape | the RISC idiom of naming the subject *inside* the event payload (an RFC 9493 Subject Identifier object) rather than via a top-level `sub_id` |
| `multi_event.json` | Synthetic | the headline receiver pattern: several events of which the recognized CAEP/RISC types decode to typed values while an unregistered CAEP `credential-change` event stays raw and round-trips byte-stably |

The CAEP/RISC event-type URIs are the real public identifiers under
`schemas.openid.net`, but the payloads are synthetic and the subjects use
the reserved example domains; no real subject data appears. The fixtures
are not imported from any sibling library — feeding a transport library's
own bytes in would invert the dependency direction (the SET-envelope
layer must not depend on the transport above it), so the interop boundary
is proven with hand-authored fixtures instead.

The synthetic fixtures use the `https://schemas.example.com` and
`https://issuer.example.com` / `https://receiver.example.com` example
domains (RFC 2606 reserves `example.com`); their event-type URIs are
illustrative and are not registered IANA event types. They never carry
real subject data.

The byte-stability assertions in the tests pin the canonical (compact)
bytes of each event payload: because `Events` values are held as
`json.RawMessage`, an event payload — including one whose event-type URI
this build does not recognize — survives a `Parse` → `Encode` round-trip
with its member order preserved and its values unchanged, which is the
property `json.RawMessage` buys over `map[string]any` (which would
reorder keys on encode). `Encode` re-serializes the claims set compactly
and compacts each `RawMessage` member to its canonical form, so the
fixtures are free to be pretty-printed; document-level whitespace is not
preserved and is not asserted. The tests additionally confirm
`Parse → Encode → Parse` is a fixed point.
