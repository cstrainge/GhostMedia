# 03. TCP control protocol

## 1. Transport and framing

Control runs only inside the mutually authenticated TLS 1.3 connection defined in
document 02. The Apple output server listens; Windows initiates. TCP byte order is
big-endian. A control frame is:

```text
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+-------------------------------+
|                    length (u32)                                |
+-------------------------------+-------------------------------+
| UTF-8 JSON text, exactly `length` bytes                         |
+---------------------------------------------------------------...
```

`length` excludes itself, MUST be 2 through 65,536 inclusive, and is checked
before allocation. A connection has at most one incomplete frame, one fixed
65,536-byte receive buffer, and a 2-second deadline to finish that frame after
its length has been read. It MUST NOT allocate proportionally to a declared
length, queue additional bytes as parsed frames, or retain a failed frame. A peer
that exceeds either bound is disconnected without a response.

JSON is a UTF-8 object per [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259).
No BOM, compression, concatenation, JSON text sequence, comments, NaN, Infinity,
duplicate object member names, unpaired UTF-16 surrogate, or non-finite number is
permitted. In v1 every message schema is closed: a member not listed for that
message is a `BAD_REQUEST`. This deliberately makes an implementation reject a
future major's message until it negotiates that major. Required members and their
JSON types are checked before application dispatch. Integer fields use JSON's
plain decimal integer grammar (no fraction or exponent), are range-checked before
conversion, and strings are Unicode scalar values with the limits stated below.

Before materializing application objects, a streaming parser MUST enforce all of
these limits: depth at most 16; at most 32 members in any object and 64 members in
the whole message; at most 8 array elements; at most 4,096 bytes for any string
unless a smaller field limit applies; and at most 8,192 bytes for a v1 message.
The sole exception is `session.hello`, which may be 12,288 bytes to accommodate a
future capability list but is still subject to the same structural limits. Parser
work, including UTF-8 validation, is charged against the connection's request
budget; parsing an invalid frame cannot reset that budget.

Frames may be segmented/coalesced arbitrarily by TCP. Maximum 16 parsed frames
may wait for application dispatch, occupying at most 128 KiB in total; an
overfull queue disconnects the peer. A response uses the request's `id`; events
omit `id`. The connection processes requests in frame order. A peer MUST NOT issue
a second mutating request until it has received the first response. `ping` and
`status.get` may be outstanding concurrently, up to four total requests.

Each authenticated connection is limited to 20 valid requests per rolling second
with a burst of 40, and to four state-changing requests per rolling second with a
burst of 8. `ping` is additionally limited to one per second, `status.get` to two
per second, and `stream.open` to two per 10 seconds. Exceeding a rate limit returns
`LIMIT_EXCEEDED` once if a response can be formed cheaply; a second excess within
one minute disconnects the peer. Invalid frames and invalid requests count toward
the same budget. These bounds apply independently of the TLS-handshake limits in
document 02.

## 2. Common envelope

Every request and response has `v:1` and a lowercase dotted `type` string no
longer than 64 ASCII bytes. Every request has an `id` in 1..4,294,967,295. IDs
MUST be strictly increasing over the connection lifetime; an ID that is not larger
than the last accepted ID is `BAD_REQUEST` and disconnects after its response. This
permits the server to enforce uniqueness with one integer rather than an unbounded
replay cache; callers must not treat IDs as a replay facility. Response type is
`result` or `error`. Event type begins `event.`. Fields shown as decimal strings
exist because JSON number consumers may lose exact 64-bit precision.

```json
{"v":1,"id":7,"type":"status.get"}
{"v":1,"id":7,"type":"result","result":{"...":"..."}}
{"v":1,"id":7,"type":"error","error":{"code":"RESOURCE_BUSY","message":"...","retryable":true}}
{"v":1,"type":"event.stream.stopped","stream_id":8,"reason":"REMOTE_OUTPUT_LOST"}
```

`message` is diagnostic UTF-8 limited to 256 bytes and MUST NOT contain keys,
audio data, certificate material, raw packet bytes, or OS paths. Clients must
make decisions on `code`, not prose. A received event is advisory; `status.get`
is authoritative after ordering with its response.

All v1 strings have these additional exact limits: fixed enumerations are ASCII
and case-sensitive; a displayed `peer_id` is exactly 52 lowercase RFC 4648 base32
ASCII bytes without padding (the SHA-256 SPKI digest defined in document 02);
`session_id` is exactly 32 lowercase hexadecimal ASCII bytes; UUID text is exactly
36 lowercase ASCII bytes in canonical 8-4-4-4-12 form; decimal u64 strings are
1 through 20 ASCII digits without leading zero except `"0"`; and opaque `reason`
strings are ASCII 1 through 64 bytes. `profile` contains only the fields displayed
in section 4.2. An implementation MUST reject `null` wherever a field is not
explicitly optional.

Every event also has `v:1` and is subject to the same closed-schema rule. A
`result` has exactly `v`, `id`, `type`, and `result`; an `error` has exactly `v`,
`id`, `type`, and `error`; and `error` has exactly `code`, `message`, and
`retryable`. `retryable` is a JSON boolean. The result object is closed and has
only the following per-request fields:

| Request | Result fields (all required unless noted) |
| --- | --- |
| `session.hello` | `version`, `role`, `server_id`, `session_id`, `boot_id`, `udp_port`, `capabilities`, `limits` |
| `transport.bind` | `udp_port`, `path_state` |
| `stream.open` | `stream_id`, `key_epoch`, `profile`, `packet_interval_us`, `path_state` |
| `stream.rekey` | `stream_id`, `key_epoch`, `state` |
| `stream.start` | `state` |
| `stream.stop`, `stream.close` | `stream_id`, `state` |
| `status.get` | `output_state`, `session_stream_state`, `transport_state`, `feedback_age_ms` |
| `ping` | `token`, `monotonic_ns` |
| `session.close` | `state` |

`server_id` is canonical lowercase UUID text and is present only in the authenticated
Apple output-server `session.hello` result. `stream_id` and `key_epoch` are integers in 1..4,294,967,295; durations in
microseconds/milliseconds are non-negative integers within u32. In the hello
result, `capabilities` has exactly boolean `audio_send`, `audio_receive`,
`microphone`, and `camera`, plus `audio_profiles`: an array of 1 through 2 closed
profile objects from section 4.2. The latter is empty when `audio_receive` is false.
`limits` has exactly integer `max_audio_subscribers`,
`playout_target_ms_min`, and `playout_target_ms_max`, each in 0..u32.
`output_state` is the Apple output server's local state: `available`, `unavailable`,
or `faulted`; session and
transport states use only values explicitly defined by their request sections.
A v1 implementation MUST document and test the exact result schema it emits; it
MUST NOT smuggle diagnostic or implementation state into a result object.

## 3. Establishing a session

Within two seconds of TLS completion, Windows sends `session.hello`; the Apple output
server must reply before any other request. A failed hello closes the TLS connection.
The claimed `role` must be compatible with the fixed endpoint role (Windows sends
`win-client`; the Apple output server returns `apple-output-server`). It is only a compatibility hint: the
TLS-authenticated SPKI and local trust record in document 02, not a claimed role or
JSON identity, authorize every operation.

```json
{
  "v": 1, "id": 1, "type": "session.hello",
  "role": "win-client",
  "client_name": "Studio PC", "versions": [1],
  "udp_port": 49152
}
```

`client_name` is a label, maximum 128 UTF-8 bytes. `versions` is a nonempty,
strictly descending unique array of integers in 1..255 and v1 requires it include
1. `udp_port` is a prebound local UDP port in 1..65535 on the TCP-selected address
family/interface. It does not validate reachability by itself. The `versions` array
contains at most 8 elements. A server does not expose per-device state, profile
details, or an allocated session ID until TLS authentication, trust lookup, role
check, and this schema validation have all succeeded.

```json
{
  "v": 1, "id": 1, "type": "result",
  "result": {
    "version": 1, "role": "apple-output-server", "server_id": "<uuid>",
    "session_id": "<32 lowercase hex>", "boot_id": "<uuid>",
    "udp_port": 51838, "capabilities": {"audio_send": false, "audio_receive": true,
      "microphone": false, "camera": false, "audio_profiles": [
        {"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,
         "channel_layout":"stereo","frames_per_packet":240}]},
    "limits": {"max_audio_subscribers": 1, "playout_target_ms_min": 15,
      "playout_target_ms_max": 120}
  }
}
```

The Apple output server allocates `session_id` before sending its response, derives no
media material until an authorized stream is opened, and retains the session for the
TCP connection lifetime. `audio_receive:false` means no local output is presently
usable; the connection remains usable for status. Windows MUST call `transport.bind`
after hello even though ports were exchanged: that commits the tuple. Before any bind
or stream request, Windows compares returned `server_id` to its configured server ID;
a mismatch closes TLS, records no new trust data, and continues discovery. Path
validation is per stream and begins only after authorized
`stream.open`.

## 4. Requests

### 4.1 `transport.bind`

Windows request:

```json
{"v":1,"id":2,"type":"transport.bind","session_id":"<session_id>","udp_port":49152}
```

The session ID must match. `udp_port` must equal hello's port in v1. The Apple output
server responds with its port and `path_state:"bound"`; it does not itself send UDP.
Calling bind twice returns the original committed tuple
and state without reopening or changing it. A different port is `STATE_CONFLICT`.
Windows sends no audio before it authenticates the specific stream's matching
`PATH_RESPONSE` and completes `stream.start`.

### 4.2 `stream.open`

After a successful `transport.bind`, Windows requests one specific profile:

```json
{
  "v":1,"id":3,"type":"stream.open","kind":"audio","direction":"win_to_apple",
  "profile":{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,
    "channel_layout":"stereo","frames_per_packet":240},
  "playout_target_ms":30
}
```

`kind` and `direction` are fixed in v1. The Apple output server verifies the locally
granted `receive_system_audio` permission, local output availability, a bound
candidate tuple, sole-subscriber ownership, full profile support, and playout range.
It reserves the subscription before responding. It returns an allocated `stream_id`,
`key_epoch:1`, canonical accepted profile, nominal packet interval, and
`path_state:"probing"`. It derives the two directional keys for that stream. Windows
begins the bounded path challenge in document 04 only after receiving this response.
A stream is
**open**, not yet sending. Duplicate open with exactly the same fields while that
stream is open returns the same result; a nonidentical open is `STATE_CONFLICT`.

Optional Opus profile exactly uses `codec:"opus"`, `sample_rate_hz:48000`,
`channels:2`, `channel_layout:"stereo"`, `frames_per_packet:480`. The Apple output
server MUST advertise it in `capabilities.audio_profiles` before accepting it. Opus is
one complete RFC 6716 packet per media datagram; no RTP payload header, aggregation,
or fragmentation is used. Decoded duration must equal `frames_per_packet`.

### 4.3 `stream.start`, `stream.stop`, and `stream.close`

`stream.start` has `stream_id` and Windows-owned `first_media_timestamp`, a decimal
u64 source-frame value after conversion to the negotiated network sample rate. It
requires Windows to have authenticated the matching `PATH_RESPONSE` for that stream
and epoch. The Apple output server validates the value's syntax, records it only as
the sender's declared start boundary, flushes old receiver playout state, and returns
`state:"started"`. After that response Windows may send AUDIO beginning with exactly
that timestamp. The Apple media receiver MUST NOT generate a substitute source
timestamp. Starting an already started stream is idempotent only with the same start
timestamp.

Before sending `stream.stop`, Windows stops send pacing, releases no ownership, and
flushes its capture-to-network queue. The Apple output server's response confirms it
will discard that stream; it flushes its jitter buffer on success. `stream.close`
implies stop, destroys stream-specific state, and releases sole-subscriber
ownership. Both are idempotent only while their session remains alive. A packet
for a closed stream is dropped. A start after stop restarts the same open stream
with the next valid source timestamp; the receiver treats this as a discontinuity.

### 4.4 `stream.rekey`

Windows media sender detects the 30-minute, 2^32-packet, and sequence-exhaustion
limits in document 02 and sends `stream.rekey` before it would exceed any of them.
The request has exactly `stream_id` and `key_epoch` (equal to the current epoch plus
one), for example

```json
{"v":1,"id":8,"type":"stream.rekey","stream_id":1,"key_epoch":2}
```

The Apple output server verifies the exact next value and derives the new epoch's
directional keys. Windows derives the same keys, then sends a fresh Windows-to-Apple
`PATH_CHALLENGE` under the new epoch. The Apple media receiver returns its
`PATH_RESPONSE`; Windows authenticates that response and only then switches at the
next packet boundary, preserving its source media-timestamp continuity. The Apple
media receiver accepts old and new epochs for a five-second overlap without flushing
its jitter buffer or calling `stream.start`. A rekey request with another value is
`STATE_CONFLICT`; a duplicate committed request returns the same result. Both sides
erase old epoch keys and path state after the overlap. Failure to complete the new
path validation before the old epoch limit stops and closes the stream.

### 4.5 `status.get`, `ping`, and `session.close`

`status.get` requires the separate locally granted `view_status`
permission. Its v1 response is intentionally small: Apple output state (`available`,
`unavailable`, or `faulted`), whether *this session* owns an active stream,
transport state for this session, and a coarse `feedback_age_ms` in 0..6000.
It never reveals another peer's identity, stream, counters, timestamps, audio,
secrets, detailed driver faults, host paths, or network addresses. A peer that has
`receive_system_audio` but lacks `view_status` may use `stream.open` and
learn only its resulting error; `status.get` returns `FORBIDDEN`.

`ping` request contains `token`, an ASCII string of 1..64 bytes chosen by sender.
The result echoes `token` and includes receiver `monotonic_ns`; it is liveness,
not a clock synchronization measurement. Send while idle every 2 seconds. A peer
MUST reply within 500 ms under normal load.

`session.close` has optional `reason` (max 64 ASCII bytes). Reply, stop all
streams, erase media keys, close TLS, and withdraw no mDNS record. Once sent,
the requester accepts either the response or connection close as success.

## 5. Events and error codes

Events are ordered with responses over the TCP byte stream. Events are emitted
only for the recipient's own session; `event.output.state` exposes only the three
Apple output states and a fixed reason enumeration, never a platform error:

| Event | Required fields | Meaning |
| --- | --- | --- |
| `event.stream.started` | `stream_id`, `first_media_timestamp` | Apple received the first AUDIO; timestamp is the observed Windows sender value |
| `event.stream.stopped` | `stream_id`, `reason` | Sender stopped; receiver flushes this stream |
| `event.output.state` | `state`, `reason` | Apple output availability changed |
| `event.session.expiring` | `reason`, `deadline_monotonic_ns` | reconnect before key/session limit |

`OK` is never an error. Defined error codes are `BAD_REQUEST`, `UNSUPPORTED_VERSION`,
`UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `STATE_CONFLICT`, `RESOURCE_BUSY`,
`DEVICE_UNAVAILABLE`, `PATH_UNVALIDATED`, `UNSUPPORTED_PROFILE`, `LIMIT_EXCEEDED`,
`TIMEOUT`, and `INTERNAL`. `BAD_REQUEST`, `UNAUTHORIZED`, `FORBIDDEN`, and
`UNSUPPORTED_VERSION` are not retryable. `RESOURCE_BUSY`, `DEVICE_UNAVAILABLE`,
`PATH_UNVALIDATED`, and `TIMEOUT` may be retryable. `INTERNAL` never exposes an
implementation exception. Protocol parse failure closes the connection instead
of trying to send a possibly unsynchronized error frame.

## 6. Control liveness

TCP EOF, TLS alert, failed ping, or no received valid control frame for 6 seconds
ends the session. An active stream additionally sends `ping` every 2 seconds.
Windows media sender may declare remote output lost based on Apple receiver feedback
but still keeps control alive until its timeout. TCP is never used for sample retransmission,
loss repair, or media carriage.
