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
