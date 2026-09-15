# Burner Messenger: architecture and protocol v0.1

**Status:** design draft, 2026-09-15. **Not production-ready and not security-audited.**

Labels used below:

- **PROVEN PRACTICE** — an established construction or operating pattern; its use here still needs a correct implementation and audit.
- **REASONABLE ENGINEERING** — a defensible composition/trade-off, but not a proven security theorem for this whole system.
- **OPEN RESEARCH / EXPERIMENTAL** — unresolved or insufficiently validated at the scale/threat level proposed.
- **IMPOSSIBLE UNDER THE STATED CONSTRAINTS** — cannot be honestly guaranteed without relaxing a requirement.

The governing rule is: **no central backend belongs to the core trust model, but untrusted peers may optionally assist transport and storage; clients independently verify every security-sensitive claim.** “P2P” does not imply anonymity, and E2E encryption protects content, not all metadata.

## 1. Executive architecture summary

The recommended system is **P2P-first**, not strict P2P. A burner is a locally generated, time-bounded identity container with no global name or account. Contacts pair by QR/NFC/local transfer when possible, or exchange an opaque rendezvous capability out of band. Peers attempt direct QUIC, use ICE-like address discovery and hole punching, then an untrusted peer relay. Offline delivery is optional and uses capability-addressed, encrypted, fixed-bucket mailbox objects stored by untrusted peers.

Content uses an authenticated hybrid initial handshake (X25519 + ML-KEM-768), HKDF-SHA-256 key separation, then a reviewed Double Ratchet implementation with ChaCha20-Poly1305. The PQ component improves initial “harvest now, decrypt later” resistance; a classic Double Ratchet alone does **not** maintain post-quantum security indefinitely. Signal separates asynchronous [PQXDH](https://signal.org/docs/specifications/pqxdh/) from its [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) and now documents a post-quantum ratchet composition; that separation is the reference, not permission to copy an unreviewed variant.

Identity/resource creation uses an Equihash-family memory-hard proof bound to the ephemeral public key, network, purpose and time epoch. Peers verify the proof and impose their own quotas. This makes resources costly; it neither proves personhood nor prevents Sybils. Parameter selection, mobile viability and adversarial economics are **OPEN RESEARCH / EXPERIMENTAL**.

### Property matrix

| Property | Mechanism | Classification | Not provided |
|---|---|---|---|
| Content confidentiality/integrity | Hybrid authenticated handshake + Double Ratchet AEAD | **PROVEN PRACTICE** primitives | Anonymity, endpoint safety |
| Endpoint authentication | QR safety number or authenticated ephemeral signing key | **PROVEN PRACTICE** | Human identity unless verified out of band |
| Identity privacy | Per-burner and per-contact keys; no searchable names | **REASONABLE ENGINEERING** | Unlinkability against a global observer |
| Metadata privacy | Opaque rendezvous, padding, relays, optional cover traffic | **REASONABLE ENGINEERING** | Perfect traffic-analysis resistance |
| Sybil resistance | Verifiable work + peer-enforced quotas/diversity | **OPEN RESEARCH / EXPERIMENTAL** | One-human-one-identity |
| Availability | Direct path, multi-peer rendezvous, optional relay/mailbox | **REASONABLE ENGINEERING** | Availability against network blocking |
| NAT traversal | ICE-like candidates, UDP hole punching, relay fallback | **PROVEN PRACTICE** | Guaranteed direct connectivity |
| Offline delivery | Untrusted encrypted mailbox | **REASONABLE ENGINEERING** | Zero third-party storage |
| Ephemerality | TTLs, key erasure, encrypted local state, minimal logs | **REASONABLE ENGINEERING** | Guaranteed disappearance from all devices |

## 2. Threat model

| Attacker | Protected | Not protected / residual leakage |
|---|---|---|
| 1. Passive Internet observer | TLS/QUIC and message E2E hide content and protocol payload | IP pairs, timing, volume, packet sizes, DHT/relay use; direct peers expose each other’s IPs |
| 2. Malicious peer | AEAD, transcript binding, replay windows and ratchet state protect other sessions | The peer sees messages legitimately sent to it, may screenshot/export, lie, withhold, reorder, fingerprint or report abuse |
| 3. Mass Sybil attacker | Valid proofs and admission quotas raise marginal cost | Well-funded parallel hardware still creates many identities; no proof of unique humans |
| 4. Spam/flooding attacker | Per-resource proofs, bounded parsing, quotas, `MAX_SKIP`, mailbox caps | Can consume bandwidth/CPU up to admission limits and attack many independent peers |
| 5. Compromised endpoint | Past deleted ratchet keys may retain forward secrecy | Current plaintext, keys, contacts, notifications, screenshots and future input are lost; hardware key stores do not save a live compromised process |
| 6. Old device-database thief | DB encryption and wrapped keys protect without unlock material | Weak device PIN, backed-up wrapping keys, WAL/pages, crash dumps and undeleted exports may leak; secure deletion on flash is not guaranteed |
| 7. Global passive observer | Padding/relays obscure content and some direct relationships | Long-term timing correlation is generally effective; low-latency anonymity cannot promise global-observer unlinkability without costly mixing/cover traffic |
| 8. Fraction of DHT nodes | Encrypted opaque records hide contents; replication/diverse lookup resists partial failure | Nodes see lookup keys, requester IP/timing and can drop, delay, replay or bias routes; enough nearby Sybils can eclipse a key |
| 9. Modified client | Peers verify signatures, proofs, AEAD and limits instead of trusting UI delay | Attacker skips local UX delay and local rate limits; can still solve/parallelize valid proofs |
| 10. Malicious relay/mailbox | E2E encryption prevents plaintext/key access; signed envelopes expose tampering | Relay sees source IP (unless chained), timing, sizes, mailbox capability/address and retrieval patterns; can delete, replay or withhold |
| 11. UDP/direct-path blocker | Optional TCP/TLS-like or privacy relay fallback can preserve service | Strict-P2P mode becomes unavailable; a censor blocking bootstrap/relays can deny service |

Compromised endpoints and a global passive observer are explicit non-goals for full protection. Availability is never a cryptographic guarantee.

## 3. Detailed system architecture

```text
┌───────────────────────────────────────────────────────────────┐
│ Application UI [trusted local]                               │
│ burner lifecycle · contacts · consent · expiry               │
├───────────────────────────────────────────────────────────────┤
│ Conversation/session manager [trusted local]                  │
│ sequencing · replay window · queues · resource limits         │
├───────────────────────────────────────────────────────────────┤
│ Handshake + ratchet [trusted, externally audited]             │
│ Ed25519 auth · X25519 + ML-KEM · HKDF · Double Ratchet · AEAD │
├───────────────────────────────────────────────────────────────┤
│ Canonical envelope codec [locally checked/remotely verifiable]│
├───────────────────────────────────────────────────────────────┤
│ QUIC secure transport [untrusted for message confidentiality] │
├───────────────────────────────────────────────────────────────┤
│ Candidate gathering + hole punching [untrusted assistance]    │
├──────────────────┬───────────────────────┬────────────────────┤
│ Direct P2P       │ Peer relay [optional] │ Privacy path [opt.] │
├──────────────────┴───────────────────────┴────────────────────┤
│ Kademlia rendezvous [untrusted, records cryptographically     │
│ checked] · encrypted mailbox [optional/untrusted]             │
└───────────────────────────────────────────────────────────────┘
```

**STRICT P2P** means no relay, mailbox, push provider or third-party path: both peers must be simultaneously online and mutually reachable. **P2P-FIRST** means direct is preferred, while untrusted peers may relay/store opaque ciphertext. On mobile, strict P2P conflicts with NATs, OS suspension and offline delivery; it is a selectable reduced-availability mode, not the default.

Trust boundaries: UI, secrets, ratchet and policy validation are local trusted components. DHT nodes, address-discovery peers, relays and mailboxes are untrusted. Proofs, records, handshakes and envelopes are remotely verifiable. Connectivity helpers are optional but practically required for reliable Internet/mobile operation.

## 4. Identity lifecycle

1. **Create — REASONABLE ENGINEERING.** Generate `burner_root` with the OS CSPRNG. Derive domain-separated seeds with HKDF; generate a burner-scoped Ed25519 authentication key, contact-specific key material and rendezvous capabilities. Never derive two algorithms’ keys from the same bytes without labeled KDF separation.
2. **Work — EXPERIMENTAL.** Compute an identity stamp bound to `network_id || protocol_version || burner_auth_pub || epoch || expiry`.
3. **Introduce.** QR/NFC encodes protocol version, burner authentication fingerprint, one-time invitation secret, initial rendezvous capability and expiry. Internet sharing transports the same high-entropy capability; it is not a username.
4. **Establish.** Consume the invitation once locally, verify the transcript/fingerprint, and derive a distinct conversation ID and keys. A contact never receives `burner_root`.
5. **Rotate.** Rotate rendezvous slots frequently and signed prekey bundles at least daily; conversation ratchets rotate per message. Do not publish a stable burner key as a DHT lookup key.
6. **Expire.** Stop advertising; tombstone local queues; delete wrapped DB/attachment keys and ratchet state. Expiry uses bounded clock-skew windows and monotonic clocks for local timers.
7. **Destroy.** Crypto-erase wrapping keys, compact best-effort storage, clear notifications/clipboard, and explain that remote copies and flash remnants may survive.

A long-lived public key correlates sessions wherever it appears. The burner authentication key may correlate contacts within that intentionally bounded burner lifetime. Stronger isolation uses a unique authentication key per contact, authenticated by the QR invitation secret; it sacrifices easy multi-contact recovery.

## 5. Contact and discovery protocol

### Mode A: private out-of-band introduction — PROVEN PRACTICE

QR/NFC/local transfer carries a 256-bit invitation capability plus an authentication fingerprint and expiry. Both endpoints display a short safety number derived from the full handshake transcript. The invitation is single-use from the clients’ perspective; reuse cannot be globally prevented without shared storage, so a consumed-invitation warning is local only.

### Mode B: Internet rendezvous — REASONABLE ENGINEERING

There is no `find Alice`. For rendezvous secret `R` and 15-minute slot `s`:

```text
lookup_key = BLAKE3(key=R, "rv-key" || network_id || s)
record = {
  v, slot, expires_at, sequence,
  padded_ciphertext = XChaCha20-Poly1305(
      key=HKDF(R,"rv-record"||s),
      nonce=random24,
      plaintext={candidate_hints, relay_hints, signed_key_package},
      aad=canonical(v,lookup_key,slot,expires_at,sequence)),
  nonce, resource_pow
}
```

Use a deterministic canonical codec (restricted CBOR) with duplicate-key rejection. Lookup keys rotate by slot. Records expire after at most 30 minutes; accept current/adjacent slots for clock skew. The inner key package is signed and binds network, slot, sequence and expiry. Old signed records therefore replay only inside a narrow accepted window. Endpoints fetch several replicas and require consistent, valid records rather than trusting a single route.

- **Squatting:** guessing a 256-bit lookup capability is infeasible; a party holding `R` is authorized and can race records. DHT nodes accept bounded immutable values, not unauthenticated destructive replacement.
- **Sybil/eclipse:** proof-gated writes, k-bucket IP/ASN diversity, multiple bootstrap views, disjoint iterative lookups and result comparison raise cost but do not solve eclipse attacks. This remains **OPEN RESEARCH / EXPERIMENTAL**.
- **Malicious routing nodes:** validate everything end-to-end; retry diverse routes; never treat absence as proof a contact is offline.
- **Correlation:** a DHT node can link repeated access to the same slot key and IP. Rotation narrows the window; relayed queries and cover lookups cost latency/bandwidth and still do not defeat a global observer.

A Kademlia network needs bootstrapping. Shipping multiple community-operated bootstrap addresses is infrastructure, but not a trusted authority. DNS-free pinned bootstrap keys, LAN/mDNS discovery, QR-carried bootstrap peers and user-added peers reduce concentration.

## 6. Verifiable client-side work and abuse resistance

### Three distinct claims

**A. UX friction — REASONABLE ENGINEERING:** the official client targets, for example, 2–5 seconds and 64–256 MiB based on battery/thermal class. A modified client can skip this entirely.

**B. Protocol-enforced cost — REASONABLE ENGINEERING:** peers accept an identity, DHT write, mailbox deposit or unsolicited contact request only if its proof meets their locally configured minimum. Verification cannot trust reported duration or RAM.

**C. Sybil resistance — OPEN RESEARCH:** proof raises marginal cost; it does not bind identities to humans or cap a funded attacker’s influence. Influence must also be bounded by per-resource quotas, routing-table diversity and admission policies.

### Stamp v1

Use a reviewed **Equihash-family** solver/verifier, not a home-grown puzzle:

```text
challenge = H("burner-work-v1" || network_id || purpose ||
              subject_hash || epoch || expires_at || params_id)
proof = {v=1, algorithm=EQUIHASH, params_id, epoch, expires_at,
         subject_hash, nonce, solution_indices}
```

The verifier reconstructs the challenge, rejects noncanonical/duplicate indices, checks epoch/expiry and verifies the generalized-birthday solution. Binding `purpose` prevents reusing identity work as mailbox/DHT work; binding `subject_hash` prevents transfer; short epochs limit precomputation. The original [Equihash paper](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_biryukov.pdf) describes asymmetric memory-hard work with efficient verification.

Do **not** use “run Argon2id once and send the hash” as the primary network stamp: [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) establishes Argon2’s memory hardness, but a peer must recompute an expensive function to verify such a stamp, enabling verifier-exhaustion DoS. Argon2id remains appropriate for local passphrase-based key wrapping.

Parameters are versioned fixed floors per protocol release; peers may demand more work but must advertise limits. There is no trustworthy decentralized real-time “global difficulty” oracle. Mobile clients can defer work until charging, choose shorter burner lifetime within accepted classes, or decline participation. ASIC/GPU resistance is relative, parameters age, browser/JIT implementations differ, and parallel attackers retain an advantage.

### Remotely enforced limits

- Before expensive parsing/crypto, cap packet size and verify a cheap cookie/token.
- Per accepted conversation: token buckets for bytes/messages/connections.
- Unsolicited request: dedicated fresh stamp; identity stamp alone is insufficient.
- DHT node: maximum value size, TTL, writes per subject/prefix and total storage; eviction is local.
- Mailbox: deposit capability, per-object proof, fixed maximum object size, total mailbox quota and expiry.
- Session: `MAX_SKIP = 1000`, at most 200 stored skipped keys, at most 4 concurrent handshakes per peer, bounded reassembly and decompression disabled before authentication.

An attacker may ignore its own limits; every receiving peer enforces these limits before allocating the corresponding resource.

## 7. NAT traversal and transport

**PROVEN PRACTICE** for ICE-like traversal and relay fallback; **REASONABLE ENGINEERING** for decentralized helper selection.

Connection order:

1. direct IPv6 candidates;
2. direct IPv4 candidates;
3. QUIC/UDP hole punching using peer-observed server-reflexive candidates;
4. an authenticated simultaneous-connect procedure through an existing relay path;
5. temporary peer circuit relay;
6. optional privacy relay/overlay, possibly over TCP/TLS when UDP is blocked.

This follows ICE concepts ([RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html)) without making one central STUN/TURN service authoritative. Address-discovery peers are selected from multiple routing regions and only report observed addresses. libp2p documents [decentralized hole punching](https://docs.libp2p.io/concepts/nat/hole-punching/) and [circuit relay](https://docs.libp2p.io/concepts/nat/circuit-relay/); reuse audited implementations where they fit rather than recreating NAT state machines.

Endpoint-independent NATs often permit UDP punching. Symmetric NATs allocate destination-specific mappings, CGNAT shares scarce public addresses, enterprise/mobile firewalls may block unsolicited UDP, and suspended phones cannot coordinate a punch. Therefore direct reachability is never assumed. QUIC ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)) supplies congestion control, authenticated transport and migration; application E2E encryption remains mandatory because relays terminate/forward transport paths and transport identity is not conversation identity.

## 8. Cryptographic protocol

### Initial authentication and agreement — PROVEN PRACTICE components, composition requires audit

- Ed25519 burner/contact authentication key signs short-lived key packages.
- X25519 ephemeral-static and ephemeral-ephemeral DH provide classical authenticated key agreement when signatures/fingerprints are verified.
- ML-KEM-768, standardized in [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), contributes a post-quantum shared secret.
- `handshake_secret = HKDF-Extract(transcript_hash, x25519_secrets || mlkem_secret)`; labeled HKDF-Expand outputs root, header, confirmation and transport-binding keys.
- Both sides send key-confirmation MACs over the entire canonical transcript: identities, invitation, algorithms, key packages, roles and versions. Reject downgrade, reflection and unknown critical fields.

Hybrid secrecy holds if at least one combined KEM remains confidential **and** the composition is correct. Ed25519 authentication is not post-quantum. PQXDH is a useful asynchronous reference, but this protocol must use a reviewed library/spec mapping rather than claim compatibility.

### Ongoing encryption and post-compromise security — PROVEN PRACTICE when using a reviewed Double Ratchet

Initialize the Double Ratchet root from the confirmed handshake. Use X25519 DH ratchet keys, HKDF-SHA-256 chain/root KDFs, and ChaCha20-Poly1305 with unique 96-bit nonces derived from message keys/counters according to the selected reviewed implementation. Delete each message key after use. DH ratchet turns can restore future secrecy after an attacker loses access and an uncompromised ratchet exchange occurs; they cannot repair plaintext already observed during compromise.

An ML-KEM initial handshake provides no lasting PQ post-compromise guarantee by itself. Integrating Signal’s newer post-quantum ratchet approach is a separate reviewed milestone, not “add a KEM every N messages.” Signal’s [SPQR description](https://signal.org/blog/spqr/) documents why the ratchet layer is distinct.

## 9. Compact message envelope

**REASONABLE ENGINEERING.** This is a proposed bounded profile, not an audited wire format.

Transport sees only a fixed-width outer routing hint and padded ciphertext:

```text
OuterEnvelope v0.1 {
  version: u8 = 1
  route_tag: bytes16       // rotates; not a global identity
  bucket_class: u8         // 512, 1K, 2K, 4K, 8K, 16K, 32K, 64K
  opaque: bytes[bucket]
}

EncryptedInner {
  conversation_id: bytes16
  ratchet_header: {dh_pub: bytes32, previous_chain_len: u32, message_no: u32}
  message_id: bytes16
  kind: u8
  created_at_bucket: u32   // coarse and optional
  expires_after: u32       // relative policy, authenticated
  body_len: u32
  body: bytes
  random_padding: bytes
}
```

Authenticate the canonical outer header, transport/session binding and ratchet header as AEAD associated data. Bounds are checked before allocation. Conversation IDs, exact sequence data and expiration remain encrypted where routing permits. Bucket padding reduces length precision but does not hide timing, count or the selected bucket.

## 10. Ratchet state machine

**PROVEN PRACTICE** for a reviewed Double Ratchet; **REASONABLE ENGINEERING** for crash-safe persistence and the concrete limits below.

```text
EMPTY -> INVITED -> HANDSHAKING -> ESTABLISHED -> CLOSING -> DESTROYED
                         |              |
                         +-> FAILED     +-> REKEY_REQUIRED
```

- **A creates session:** validate invitation/key package/expiry/proof; generate ephemeral X25519 and ML-KEM encapsulation; persist pending transcript atomically.
- **A sends first message:** after key confirmation, derive and erase sending message key; commit chain counter before network send so a crash never reuses a key.
- **B receives:** authenticate transcript/envelope, check replay ID/counters, derive receive key, decrypt, atomically advance and erase old key.
- **B responds:** create a fresh DH ratchet key, mix DH output into root/sending chain, then encrypt.
- **Ratchet advances:** receiving a new authenticated DH public key closes the old receive chain, performs DH/root KDF, and creates the next receive chain.
- **Out of order:** derive skipped keys only up to `MAX_SKIP=1000`; retain at most 200 keys and for at most 7 days; index by ratchet public key + message number; erase upon use.
- **Lost message:** later messages can use bounded skipped-key derivation. Beyond limits, request a signed in-session rekey rather than unbounded work.
- **Reconnect:** transport can change without resetting the conversation ratchet; authenticate a channel-binding challenge to prevent session confusion.
- **Rekey:** confirmed control message establishes a new hybrid root, cross-signed by current session keys; keep a short rollback window against loss, then erase old state.
- **Compromise:** mark session unsafe; a later uncompromised DH ratchet may restore future classical secrecy, not past/current secrecy. PQ restoration requires a reviewed PQ ratchet.
- **Destroy:** send an advisory authenticated close if desired, erase local state/keys, reject future sequence numbers. Remote deletion is not enforceable.

## 11. Offline mailbox

**No offline delivery — IMPOSSIBLE UNDER STRICT P2P:** if B is offline, some third party must retain data or A must keep retrying until B returns.

Supported options, in increasing availability: no mailbox; a trusted friend/device; a temporary untrusted peer; replicated distributed encrypted mailboxes; optional operated relays outside the trust core.

Recommended “dumb mailbox” object — **REASONABLE ENGINEERING**:

```text
mailbox_slot = HMAC(mailbox_capability, epoch || counter)
deposit = {slot, expiry, bucket, opaque_e2e_envelope, deposit_pow, auth_tag}
```

The capability is contact-specific and rotates. Deposit authorization is a derived one-way token so a mailbox cannot forge future slots. Recipient polls several chosen mailboxes over a relay, validates the inner envelope, deduplicates message IDs and sends an unlinkable deletion capability. Objects expire regardless of deletion acknowledgment.

The mailbox cannot read or modify authenticated content, but sees the depositor’s IP unless relayed, retrieval IP, timing, selected bucket, expiry, repeated slot access and availability. It can drop/replay/withhold. Replication improves availability while exposing metadata to more parties. Briar's separate [Mailbox implementation](https://code.briarproject.org/briar/briar-mailbox) is useful prior art for an always-on helper device, not proof of the privacy properties proposed here. Private information retrieval, mixnets and anonymous credentials are **OPEN RESEARCH / EXPERIMENTAL** additions.

## 12. Metadata and privacy modes

**REASONABLE ENGINEERING** for modes 1–2; **OPEN RESEARCH / EXPERIMENTAL** for meaningful global-observer resistance in mode 3.

| Mode | Path | Leakage | Cost |
|---|---|---|---|
| 1. Direct P2P | direct QUIC | Both peers and observers learn endpoint IPs; timing/online status are obvious | Lowest latency/data/battery |
| 2. P2P + privacy relay | one or two independently selected relays | Each relay sees one side or adjacent hop; timing correlation remains | More latency, relay availability/bandwidth |
| 3. Maximum resistance | multi-hop overlay, padded epochs, batching, dummy traffic, delayed mailbox polling | Reduces local observer/linkability; global correlation remains a serious risk | High latency, battery/data usage; poor background-mobile fit |

Never place OS advertising IDs, phone numbers, push tokens, stable device IDs or stable public keys in DHT/envelopes. Quantize expiry, pad messages, jitter polling and rotate paths. Diagnostic logs default off and redact IPs, route tags, keys, ciphertext fingerprints and exact timing. No analytics or address-book upload.

## 13. Mobile constraints

The lifecycle handling is **PROVEN PRACTICE**; reliable always-on background P2P without OS assistance is **IMPOSSIBLE UNDER THE STATED CONSTRAINTS**.

| State | Honest expectation |
|---|---|
| Foreground active chat | Direct/relay QUIC, DHT refresh and ratchet messaging work normally |
| Background | Short grace periods only; scheduled work is opportunistic and OS-controlled |
| Device offline | No direct receive; mailbox can retain ciphertext |
| App terminated | No reliable sockets or polling; a push provider or user reopening the app is needed |
| Device rebooted | Keystore-protected state can recover after unlock; networking resumes only when OS permits |

Android documents [background execution limits](https://developer.android.com/about/versions/oreo/background); iOS exposes scheduled [Background Tasks](https://developer.apple.com/documentation/backgroundtasks), not an always-running daemon. Silent/background push is an OS/vendor-assisted wake hint, leaks a device token/timing to the provider, and is not guaranteed. A backend-independent build must accept delayed delivery until foreground execution. Persistent user-visible Android foreground services improve liveness at a battery/UX cost; iOS offers no equivalent unrestricted mode.

## 14. Local storage and endpoint security

**REASONABLE ENGINEERING.** Hardware-backed wrapping and crypto-erasure reduce exposure but cannot guarantee physical erasure.

- Store identity/contact/ratchet/pending state in an encrypted SQLite database; use a random database key wrapped by Keychain/Secure Enclave policy on Apple and Android Keystore/StrongBox where available.
- Separate attachment keys and ratchet-state keys so expiry can crypto-erase narrow scopes. Commit ratchet updates transactionally; include schema/version MACs and rollback counters where hardware support permits.
- Exclude secrets and decrypted databases from cloud/device backups by default. Document that platform migration/recovery then loses burners.
- Disable plaintext WAL/temp files, core dumps in release, verbose crypto/network logs, and secret-bearing crash reports. Fuzz corrupted databases and fail closed without resetting replay counters.
- Never put keys/messages in general clipboard by default. Redact notification previews; provide screenshot blocking on Android and warn that iOS/other cameras cannot be controlled reliably.
- On destroy, erase wrapping keys first and best-effort overwrite/delete files. Flash translation layers, snapshots, backups and RAM copies make physical secure deletion unprovable.

## 15. Sybil/spam conclusions

**OPEN RESEARCH / EXPERIMENTAL.** These policies bound resource use; they do not establish decentralized personhood.

PoW is one input to resource admission, not reputation and not identity. A botnet/ASIC operator may outspend phones; adaptive global difficulty has no trusted decentralized measurement; IP-based limits harm NATed users and leak/network-centralize identity. Use independent local policies, limited routing-table influence per network prefix/ASN, random peer selection, proof-gated writes, contact capabilities and user consent.

Do not let a high-work identity monopolize routing/storage proportionally without a hard cap. Prefer “one valid proof earns one bounded, expiring resource.” For mailbox/DHT service, require fresh purpose-bound work and cheap stateless admission cookies before expensive verification. Publish interoperable minimum parameters slowly after measurements; clients may reject overheated/low-battery work and create identities while charging.

## 16. Failure modes

- **Clock skew:** accept adjacent rendezvous epochs; use signed relative expiry once a session exists; never extend an expired signed package solely from a peer’s clock.
- **Partition/censorship:** direct and DHT fail; optional TCP/privacy bridges help but can be enumerated/blocked.
- **DHT eclipse/poisoning:** diverse bootstrap/routing, replication and signed/encrypted validation; availability may still fail.
- **Relay/mailbox loss:** retry independent providers; deduplicate; never treat relay acknowledgment as recipient delivery.
- **Ratchet state rollback/corruption:** atomic counters and authenticated DB; fail to explicit re-pair rather than risk nonce/key reuse.
- **PoW parameter split:** accept a versioned overlap window; never silently reinterpret a proof.
- **Oversized/malicious packets:** hard pre-decode bounds, canonical codec, timeouts, quotas and fuzzing.
- **Lost root/device:** no central recovery by design; contacts must re-pair.
- **Expired identity:** stop network acceptance/advertising; local clock manipulation remains possible, while peers independently apply their clocks/policies.

## 17. MVP roadmap and gates

0. **Threat model/spec — required:** protocol state machines, canonical encodings, test vectors, privacy budget, abuse economics; independent design review.
1. **LAN encrypted chat:** QR-authenticated X25519 session using an existing Noise/ratchet library; no discovery/offline claims.
2. **Internet direct:** QUIC addresses exchanged out of band; instrument metadata locally without analytics.
3. **NAT traversal:** multiple address observers, hole punching, explicit strict-P2P failure UX.
4. **Burner lifecycle:** per-contact identity, QR/NFC, encrypted storage, destroy/re-pair flows.
5. **DHT rendezvous:** opaque rotating records, adversarial test network, eclipse measurements.
6. **Verifiable PoW:** benchmark mobile/desktop energy/RAM, third-party review, peer admission policies.
7. **Mailbox/relay:** capability deposits, quotas, replication, malicious-store tests.
8. **Metadata modes:** path rotation, batching/padding, measurement against realistic observers.
9. **Mobile hardening/audits:** lifecycle testing, backup/notification review, external crypto/protocol/app audits and staged beta.

No phase inherits a “secure” label merely because the previous phase passed tests.

## 18. Suggested technology stack

| Component | Recommendation and why | Risk/license/interface |
|---|---|---|
| Core | Rust library with a narrow C ABI/UniFFI boundary | Memory safety helps, not a security proof; forbid unsafe except reviewed adapters |
| iOS/Android UI | Swift / Kotlin | Native lifecycle, keystore, networking and accessibility integration |
| Async/runtime | Tokio behind an internal executor interface | Mature Rust ecosystem; avoid leaking runtime types across core APIs; MIT |
| QUIC | [Quinn](https://github.com/quinn-rs/quinn) or platform-vetted QUIC | Mature Rust QUIC, MIT/Apache-2.0; wrap transport traits and audit configuration |
| P2P components | Selected [rust-libp2p](https://github.com/libp2p/rust-libp2p) transports, identify minimization, Kademlia, relay/DCUtR | Reuse NAT/routing machinery, but disable unnecessary identity protocols; MIT; wrap discovery/relay traits |
| Ratchet | A maintained reviewed implementation matching published test vectors | Do not implement from the prose in this document; `libsignal` is [AGPL-3.0](https://github.com/signalapp/libsignal) and not a stable general-purpose API—legal and integration review required |
| Primitives | RustCrypto/audited platform providers; NIST-standard ML-KEM implementation with KATs | Provider agility behind `CryptoProvider`; constant-time/side-channel and mobile FFI audit; verify each crate’s exact version/license |
| Encoding | Restricted deterministic CBOR implementation | Canonical subset wrapper; reject duplicate/noncanonical/unknown critical fields |
| Storage | SQLite plus reviewed encryption/key-wrapping integration | SQLite is portable; encryption extension licensing/build provenance must be reviewed; hide behind repository interface |
| PoW | Reviewed Equihash-family library after benchmarks | Experimental policy; pin/fuzz verifier; avoid unmaintained native code and bespoke WASM |

Dependency selection requires SBOM, reproducible builds, pinned checksums, vulnerability monitoring, license review and a small wrapper so protocol logic does not depend on unstable library APIs.

## 19. Comparison with existing systems (current research snapshot)

| System | Identity/centralization/discovery | Transport/offline/metadata | E2E / forward secrecy / PQ | P2P/mobile practicality |
|---|---|---|---|---|
| Signal | Server account/service and server-mediated prekeys/delivery; not a public-name DHT | Central service enables strong offline delivery; metadata mitigations are not anonymity | E2E and forward secrecy; [PQXDH](https://signal.org/docs/specifications/pqxdh/) initial agreement plus [SPQR](https://signal.org/blog/spqr/) post-quantum ratcheting | Not P2P-first; excellent mobile practicality through service/push infrastructure |
| Briar | No central account; contacts added in person or by links; peer synchronization | Tor online, Bluetooth/Wi-Fi local; [Briar’s architecture](https://briarproject.org/how-it-works/) avoids a central server, while its optional mailbox uses another device; relay/traffic metadata is reduced, not eliminated | E2E; Briar’s [BTP specification](https://code.briarproject.org/briar/briar-spec/-/blob/master/protocols/BTP.md) specifies forward-secret transport mode; no documented PQ ratchet | P2P/offline/censorship oriented; Android-focused, with helper-device cost |
| Tox | Long-lived Tox public-key ID; Kademlia-family DHT/bootstrap | Direct peer connections with relays where needed; ordinary messaging requires reachable/online peers; DHT exposes network activity | E2E; no Double Ratchet or post-quantum baseline is specified in the cited [TokTok protocol](https://toktok.ltd/spec.html), so equivalent PCS/PQ properties must not be assumed | P2P-first; weaker offline/mobile ergonomics |
| Jami | Distributed account/device model described in its [account-management documentation](https://docs.jami.net/en_US/developer/jami-concepts/account-management.html); can operate [LAN-only](https://docs.jami.net/en_US/user/lan-only.html) | Its [connection manager](https://docs.jami.net/en_US/developer/jami-concepts/connection-manager.html) covers peer connectivity, while [swarm conversations](https://docs.jami.net/en_US/developer/jami-concepts/swarm.html) synchronize state, increasing distributed retention/linkability | E2E; the cited architecture does not document a PQ ratchet, and transport/session forward secrecy must not be equated with Double-Ratchet PCS | P2P-first and multi-device practical, but less “burner minimal”; mobile helpers may be needed |
| SimpleX | No global user identifiers; invitation links and per-contact queues | Store-and-forward SMP routers are fundamental; two-hop routing separates sender and recipient IP knowledge but timing/queue metadata remains | The current official [protocol overview](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/overview-tjr.md) specifies E2E Double Ratchet, forward secrecy and post-quantum cryptography | Not direct-P2P-first; relay-dependent asynchronous delivery gives strong mobile practicality |

These are architectural comparisons, not rankings. Exact releases and deployed cryptographic versions must be re-verified before implementation decisions.

## 20. Open research questions

1. Which memory-hard stamp has safe, cheap, constant-bounded verification and tolerable iOS/Android energy/thermal behavior?
2. How should fixed proof floors evolve without a central difficulty oracle or network split?
3. What measurable eclipse resistance does the proposed Kademlia diversity policy provide under IPv6/cloud Sybils?
4. Can mailbox polling be made meaningfully unlinkable without impractical PIR/mixnet latency and battery use?
5. Which maintained ratchet library supports our required state export/atomic persistence and mobile FFI without protocol forks?
6. Should PQ authentication (signature) be added, and how can QR/key-package size remain usable?
7. Can a reviewed sparse PQ ratchet be integrated without unacceptable message/state growth?
8. What cover-traffic budget materially improves resistance to a realistic observer?
9. How are relay incentives/abuse handled without creating durable payment/account identifiers?

## 21. What not to build ourselves

- No custom cipher, MAC, KDF, KEM, signature, RNG, “BurnerCrypto” or “BurnerRatchet.”
- No custom QUIC, congestion control, ICE/hole-punching state machine or general-purpose DHT unless existing components demonstrably cannot meet the minimized protocol.
- No novel secure-deletion claims, home-grown encrypted database, parser without canonical bounds, or global adaptive PoW oracle.
- No custom anonymity network marketed as protection against a global observer.
- No protocol negotiation that permits silent downgrade, no unauthenticated expiration/algorithm fields, and no decompression before authentication.

Before production, independent reviewers must audit: handshake composition/transcripts and downgrade resistance; ratchet integration/persistence; canonical codec; DHT capability/record design; mailbox authorization; PoW verifier and DoS economics; native/FFI memory handling; storage/backup/notification behavior; update/reproducible-build pipeline; privacy claims and traffic-analysis measurements. Formal models/test vectors are required for the handshake and ratchet state transitions.

## 22. Concise protocol v0.1

### Constants

```text
NETWORK_ID = application-specific bytes32
HASH = SHA-256 (BLAKE3 allowed only where keyed-record format fixes it)
KDF = HKDF-SHA-256
CLASSICAL_DH = X25519
AUTH = Ed25519 (classical authentication only)
PQ_KEM = ML-KEM-768
AEAD = ChaCha20-Poly1305
MAX_WIRE_MESSAGE = 65536 bytes
MAX_SKIP = 1000; MAX_STORED_SKIPPED = 200
RENDEZVOUS_SLOT = 900 seconds; RENDEZVOUS_TTL <= 1800 seconds
```

### Canonical objects

All objects use a length-delimited deterministic CBOR subset: integer map keys in ascending order; no duplicate keys, indefinite lengths, floats or non-shortest integers; unknown critical fields reject. Every signed/MACed value includes `NETWORK_ID`, protocol version, object type and roles.

### Identity and invitation

`burner_root <- CSPRNG(32)`. HKDF with unique labels derives seed material; implementations generate keys through provider APIs. `BurnerCertificate = {v, auth_pub, created_epoch, expires_epoch, work}`. An invitation contains `{v, auth_fingerprint, invitation_secret32, rendezvous_secret32, expiry, supported_suites}` and is transmitted out of band. It is never published as a name.

### Work

`work.challenge = H(domain || NETWORK_ID || purpose || subject_hash || epoch || expiry || params_id)`. Accept only a canonical valid Equihash solution, supported parameters, purpose match and local epoch/expiry/difficulty policy. One proof purchases one explicitly bounded resource; peers never trust client-reported elapsed time or memory.

### Rendezvous

Compute rotating `lookup_key` and encrypted record exactly as in §5. Query at least `k` replicas over diverse routes, accept only decryptable, signed, unexpired records for current/adjacent slots, and treat no result as unknown rather than offline proof.

### Handshake

Initiator validates certificate/package/work/expiry; creates ephemeral X25519 and ML-KEM encapsulation. Responder supplies signed short-lived X25519/ML-KEM package and fresh ephemeral contribution. Both canonicalize the full transcript, combine classical and PQ secrets through HKDF-Extract, derive labeled confirmation keys, exchange confirmation MACs, and initialize a reviewed Double Ratchet only after confirmation. Any version/suite/role mismatch aborts. Exact DH tuple and KEM flow must be frozen by external review and published test vectors before implementation.

### Messaging

Each message uses and erases one ratchet message key. Outer/inner formats follow §9. AEAD authenticates version, route tag/bucket, ratchet header and channel binding. Reject replayed message IDs/counters. Bound skipped derivation and stored keys by the constants. State advancement and ciphertext enqueue are one atomic transaction.

### Transport

Try direct QUIC candidates, coordinated punching, peer relay, then optional privacy path. Authenticate every new path with a session channel-binding challenge. Transport security never replaces message E2E. Strict-P2P configuration stops before relay and explicitly sacrifices reachability/offline delivery.

### Mailbox

Mailbox is optional. Store fixed-bucket opaque envelopes under rotating capability-derived slots with deposit authorization, purpose-bound work, byte/count quotas and TTL. Recipients validate E2E envelopes and deduplicate. Mailbox acknowledgments mean “stored,” never “read.”

### Expiry/destruction

Peers independently enforce signed expiries with a documented skew window. Expiry stops new sessions/storage and triggers local crypto-erasure; it cannot force deletion on another endpoint. Destroying a burner erases root/wrapping/ratchet keys and advertisements, after which recovery is intentionally unavailable.

## Strict “100% client-side, no infrastructure” variant

**IMPOSSIBLE UNDER THE STATED CONSTRAINTS** for the full feature set. With no bootstrap nodes, rendezvous peers, address observers, relays, mailbox nodes, push providers or any always-on third party, the remaining product is:

- QR/NFC/manual address introduction only;
- LAN discovery or manually supplied reachable IP/port;
- simultaneous foreground operation on both devices;
- direct connectivity only, failing behind incompatible NAT/CGNAT/firewalls;
- no offline delivery, no reliable terminated/background mobile receive, no Internet discovery and no availability under UDP blocking;
- no network-wide anti-abuse problem to solve beyond each contacted peer’s local admission policy.

It can still provide authenticated E2E content confidentiality between two reachable foreground clients. It cannot honestly provide reliable Internet/mobile messaging. Optional untrusted peer infrastructure is therefore not a compromise of the cryptographic trust model; it is the mechanism that makes rendezvous, NAT traversal and asynchronous delivery possible.
