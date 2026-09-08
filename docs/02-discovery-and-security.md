# Discovery and Security

This specification defines discovery, trust establishment, TLS, UDP key derivation,
network exposure, and resource limits for GhostMedia protocol version 1. The words
MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## 1. Security objectives

Every enabled LAN may contain an active attacker. Discovery is only a routing hint:
it is never proof of identity, authorization, or reachability. A device may stream
only after mutual authentication and an explicit local pairing grants the required
permission. Malformed traffic, failed authentication, and exhausted budgets MUST fail
closed without blocking the Windows audio driver, allocating unbounded memory, or
accepting media.

The protocol protects control and media against passive capture, modification, replay,
and unauthenticated injection. It does not make a paired endpoint trustworthy, conceal
traffic volume, or protect a compromised computer, account, or private identity key.

## 2. Interface and firewall policy

The Apple output server is disabled on every interface until enabled by the local user. Initial
setup MUST enable only OS-classified private/home/work interfaces. Public,
captive-portal, guest, unclassified, VPN, tunnel, virtual, and metered cellular
interfaces MUST remain disabled until the user explicitly enables that interface.

Configuration stores allowlisted stable OS interface IDs, never IP addresses or
display names, plus an `allow_public_networks` flag that defaults false. On loss of
eligibility or allowlisting, the Apple output server MUST immediately stop advertisements, close
TCP and UDP sockets on that interface, discard its paths, and terminate its streams.
The peer may reconnect only through an eligible interface and a new control session.

The Apple output server MUST bind listeners and UDP sockets only to eligible
allowlisted interfaces. Its platform firewall/network permissions MUST be scoped to
those interfaces and profiles, never an any-interface or public-profile inbound rule.
Loopback is permitted only for a separate local test mode and MUST NOT advertise
DNS-SD. Discovery, listener, and UDP exposure may be disabled independently;
disabling the listener also disables advertisements that name it. Windows is a
discovery consumer and outbound client; its configured source interface is subject to
the same eligibility checks but it advertises no DNS-SD record and accepts no inbound
control listener in v1.

## 3. DNS-SD / mDNS discovery

An eligible interface MAY advertise `_ghostmedia._tcp.local.` with a generic
human-readable instance label. The label MUST be at most 48 UTF-8 bytes after NFC
normalization, have no control characters, and contain no account name, hostname,
serial, stable device ID, certificate fingerprint, address, or persistent identifier.

A service record has one SRV target and TCP port. The target is routing metadata only
and MUST NOT encode identity or user information. The TXT record MUST contain only:

| Key | Required | Value |
| --- | --- | --- |
| `v` | yes | `1` |
| `caps` | yes | ASCII exact value `audio-out` |
| `label` | no | display label, at most 48 UTF-8 bytes |

The only v1 public capability class is `audio-out`.
TXT records MUST NOT contain a peer ID, certificate/SPKI hash, static nonce,
installation ID, MAC address, OS version, username, stream state, error, or device
inventory. Actual enabled capabilities and versions remain private until TLS
authentication. A consumer ignores unknown TXT keys; a v1 producer emits none.

mDNS responses MUST remain on the query's interface, use normal mDNS conflict and
cache-flush rules, and have TTL no greater than 120 seconds. Unsolicited announcements
are limited to one per interface per 30 seconds outside the standard initial sequence
and withdrawal. mDNS MUST NOT be a pairing, wake-up, or keepalive channel.

A discovered address is untrusted. Before TCP, the client verifies that it belongs to
the selected eligible local-link interface and is neither multicast, broadcast,
unspecified, loopback, nor global/routed unless the user explicitly authorized
routed-interface mode. New DNS data never inherits trust or authorization.

## 4. Identity, trust records, and pairing

Each installation creates one non-exportable long-term Ed25519 private key in the
platform key store and a self-signed X.509 leaf certificate. V1 MUST NOT use RSA,
SHA-1, MD5, or algorithm fallback. The leaf must be X.509v3 with a critical
`basicConstraints: CA=FALSE`, critical `keyUsage: digitalSignature`, EKU containing
both `clientAuth` and `serverAuth`, a random serial of at least 64 unpredictable
bits, and a validity period no longer than 825 days. Subject and SAN MUST NOT contain
a person, host, address, account, device model, or persistent identifier. Unknown
critical extensions are invalid.

The canonical peer identifier is `SHA-256(SPKI-DER)`, encoded lowercase base32 without
padding. It is never advertised and appears only in the authenticated pairing UI.
An Apple output server also generates `server_id`, a CSPRNG UUIDv4, on its first successful
initialization. It persists the value in server-identity-protected local storage and
never derives it from the computer name, account, mDNS label, address, port, hardware
serial, or certificate. It MUST NOT advertise `server_id` in mDNS, logs, or an
unauthenticated control response. The Apple output server returns it only after mutual TLS and
local trust authorization. Windows treats it as a stable server-selection value, never
as proof of identity; the pinned SPKI and permissions remain the trust decision.
Generation and persistence MUST complete atomically before the Apple output server listens,
advertises, or accepts a control connection. If protected persistence cannot be
established or read, the Apple output server MUST fail closed rather than operate with a transient
identity.

Installation from a cloned system image MUST regenerate `server_id` before enabling
the Apple output server. Install/repair tooling exposes an explicit `reset server identity`
operation that requires local owner confirmation, stops active streams,
generates a new UUID, and records that existing client configurations must be paired
or selected again. The implementation must not claim it can reliably detect every
disk/image clone automatically.

The identity lifecycle is explicit. If the protected value is absent but protected
storage is working, the Apple output server treats that as identity loss: it generates and
persists a new value, does not retain the old value as an alias, and requires every
configured Windows client to be locally updated and paired/selected again. If storage is
unreadable, corrupted, or unavailable, the Apple output server fails closed until a local
owner explicitly repairs storage or resets server identity; it must not guess
whether an old identity is still valid. A deliberate reset has the same client-facing
result as identity loss.
Restoring the protected value from a backup restores the original server identity
only when that backup represents the same physical/logical server installation; it
does not require reconfiguration on clients that already store that value. It does
not bypass SPKI pin validation or restore a replaced peer key. Restoring the same
backup onto a different server, or any cloned image, MUST regenerate the value before
network server is enabled, since two simultaneous installations MUST NOT share a
`server_id`. If Windows sees an authenticated but unexpected value, it MUST close
the connection before binding or streaming and require local user action to replace
its configured server identity.

A trust record is keyed by the exact 32-byte SPKI digest and contains only locally
assigned label, timestamps, and permissions; it contains no address. Permissions are
local policy, not claims: `connect`, `view_status`, `receive_system_audio`,
`provide_microphone`, and `provide_camera`. All but `connect` default denied.
Forgetting or revoking `connect` immediately closes sessions, invalidates media keys,
and removes paths.

For the fixed v1 Windows-to-Apple stream, the Apple output server grants
`receive_system_audio` and `view_status` to the paired Windows client; Windows needs
only its local `connect` trust record for the selected Apple server. The future input
permissions have no v1 effect. A permission on one peer never grants a permission on
the other.

`receive_system_audio` is persistent authorization, not a hidden background grant.
Every active stream MUST produce a local, user-visible streaming indicator in the
Apple output app that names the locally assigned Windows peer label and offers `Stop
stream` and `Revoke peer` actions. The server waits for that app's ready acknowledgement
before the first audio packet. An Apple output server without an available local UI
rejects `stream.open` unless its local owner has explicitly enabled headless streaming;
headless mode records active-stream state in its configuration UI. A local owner may
globally disable new stream starts; that setting is persistent, defaults enabled after
an explicit pairing grant, and causes new `stream.open` requests to return `FORBIDDEN`.
V1 does not require approval for every reconnect, but its persistent authorization is
always inspectable and revocable.

Unpaired devices may discover one another but cannot obtain a TLS session. Pairing
is deliberately not a network protocol in v1. Before connecting, each side displays
its protocol version and exact 52-character `peer_id`. An authorized local user transfers
that value to the other machine through an independently authenticated channel or
by physically scanning a local QR code. The QR code contains only the fixed format
identifier, protocol major, and raw 32-byte SPKI digest; scanning merely fills the
local approval form.

At each machine an authorized local user compares the complete identifier, explicitly
approves it, chooses permissions, and atomically persists the trust record before
the first connection. Both machines must complete this local action. The transfer,
comparison, and approval are outside GhostMedia's network protocol, so no unknown
certificate, provisional trust record, SAS, `pair.commit`, or pairing-only TLS
exception exists. There is no TOFU, automatic pin rotation, identity import from a
network peer, or key-backup path in v1. Replacing an identity requires repeating
this local process at both machines.

## 5. Mutual TLS 1.3 validation and authorization

Control TCP uses TLS 1.3 with mutual certificate authentication and ALPN
`ghostmedia/1`. TLS 1.2, compression, renegotiation, 0-RTT, tickets, PSK
resumption, and a public-CA trust path MUST be disabled. Exactly one self-signed leaf
is presented. For every peer certificate, validate in this order:

1. Reject missing certificates, chains with additional certificates, and DER over 8 KiB.
2. Verify the leaf self-signature using its own Ed25519 public key. Reject every
   non-v1 public-key, signature, or digest algorithm.
3. Check the exact v1 extensions and constraints in section 4, including validity;
   a missing/uncertain local clock, or one uncertain by more than 24 hours, fails closed.
4. Canonicalize SPKI DER, hash with SHA-256, and compare in constant time.
5. Require an unrevoked local trust record with `connect`.
6. Complete the session only after both peers pass validation. The authenticated
   principal is the trust-record digest, never DNS, address, label, claimed ID, or role.
7. Authorize every operation against local trust-record permissions. Fields such as
   `role` and capabilities in `session.hello` are compatibility hints only and
   MUST NOT grant or widen authorization.

A TLS library unable to enforce this leaf-only validation, including rejecting system
roots, MUST NOT be used. Renewing a leaf certificate with the exact same validated
SPKI remains trusted if it still satisfies the v1 leaf profile and validity rules.
Replacing the SPKI is an identity rotation and requires explicit bilateral local
pairing. Certificate renewal MUST NOT silently widen permissions or change the
trust-record label.

## 6. Admission and resource limits

Limits apply independently per eligible interface and globally; the stricter result
wins. They are charged before allocation of TLS state, certificate parsers, receive
buffers, worker jobs, or application objects.

| Resource | Per source | Per interface | Global | Action |
| --- | ---: | ---: | ---: | --- |
| TCP accepts | 6/min | 60/min | 120/min | token bucket; close without read |
| Unauthenticated accepted sockets | 2 | 16 | 32 | close newest |
| Incomplete TLS handshakes | 1 | 8 | 16 | close newest |
| TLS deadline | 5 s | 5 s | 5 s | monotonic deadline from accept |
| Bytes before TLS completion | 32 KiB | n/a | n/a | close |
| TLS CPU work | 2/10 s | 16/10 s | 32/10 s | pre-validation token bucket |
| First valid control frame after TLS | 3 s | 3 s | 3 s | close |
| Unauthenticated outbound attempts | 2/min | 20/min | 40/min | token bucket |

Pre-auth socket receive buffers are capped at 32 KiB. I/O is nonblocking and the
verification worker pool and queues are bounded. Source limits are only mitigation:
global limits remain mandatory. At most four authenticated sessions may exist, and
only one active session per trusted peer. A replacement connects only after complete
authentication. Each authenticated session has a 128 KiB control-input budget plus
control-spec message/rate limits. Counters use monotonic time. Close on budget
exhaustion; do not wait to refill or provide detailed network errors.

## 7. UDP keying, paths, and replay

UDP starts only after a mutually authenticated, authorized TLS session negotiates a
stream. Session ID, stream ID, direction, codec, and candidate address bind to that
session; a UDP source is never trusted from its address alone.

For each stream direction derive independent AES-256-GCM and path keys with the TLS
exporter:

```
label = "EXPORTER-GhostMedia-v1"
context = SHA-256("ghostmedia/1" || session_id || uint32_be(stream_id) ||
                 direction || uint32_be(key_epoch) || sender_spki || receiver_spki)
output = TLS-Exporter(label, context, 64)
media_key = output[0..31]; path_key = output[32..63]
```

SPKI values are 32-byte SHA-256 digests in packet-direction order. `direction` is
one byte: `01` for Windows-to-Apple and `02` for Apple-to-Windows. For a direction,
the first digest is the negotiated sender and the second is the negotiated receiver;
both endpoints use the same `media_key` for that direction and epoch. The opposite
direction and every new epoch have distinct contexts and independently derived keys.
Export only after mutual authentication; never reuse output across a new control
connection or rekey. Exact binary encodings, labels, direction constants, and
exporter values MUST have public conformance vectors. Use the TLS library exporter
API; never implement it.

A new candidate path receives an encrypted `PATH_CHALLENGE` with fresh random 96-bit
value and may return only encrypted `PATH_RESPONSE`. Candidates expire in 5 seconds,
have at most 3 challenges, and receive no more than one challenge/second or eight
per stream/minute. A matching response authorizes only that IP:port for 30 seconds.
A stream has at most two valid paths. Unvalidated packets are dropped before the
jitter buffer and cannot refresh liveness.

Authenticated header data includes version, session ID, stream ID, direction, key
epoch, sequence, timestamp, and payload length. Sender sequence starts at a random
64-bit value per epoch and increments per packet; rekey before wrap, 2^32 packets, or
30 minutes. The 96-bit nonce is `key_epoch (32 bits) || sequence (64 bits)`, and
MUST never repeat under a key. Maintain a 1024-packet replay window per direction;
duplicates and old packets never reach delivery.

Unknown UDP creates no state. Cap datagrams at 1,500 bytes before decryption,
decrypted payload at negotiated maximum, input at 500 packets/s per stream and 2,000
globally. Invalid length, unknown IDs/epoch, invalid tag, replay, or failed path
validation is a silent bounded-cost drop with no queue or feedback.

## 8. Privacy and mandatory tests

Logs MUST NOT include media/plaintext control, certificates, full SPKI digests, SAS,
path tokens, exporter material, or keys. A truncated local diagnostic peer reference
is permitted only after authentication. With `connect` alone, a peer learns only
connection state and protocol version. `view_status` exposes only UI-minimal endpoint
state and MUST NOT reveal addresses, trusted peers, driver counters, stream inventory,
error history, or fingerprints. Stream permissions do not imply `view_status`.

Conformance tests MUST prove: no stable mDNS identity or ineligible-interface
advertisement; rejection of unknown/revoked pins, CA chains, intermediates, invalid
signatures, wrong EKU, CA leaves, expired leaves, unknown critical extensions, and
unsupported algorithms; no network-triggered trust creation or permission grant; all
admission limits under slowloris, TLS flood, distributed sources, malformed
certificates, and control-frame floods; no media before TLS authorization and
successful path validation; rejection of altered/replayed/old media and expired
epochs; and no driver blocking, unbounded allocation, or unbounded tasks under
hostile discovery, TCP, TLS, or UDP traffic.
