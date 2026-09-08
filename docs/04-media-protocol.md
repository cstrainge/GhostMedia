# 04. UDP media protocol

## 1. GMA/1 datagram and AEAD

GMA/1 is unicast UDP only. It uses the per-stream, directional AES-256-GCM media
and path keys from document 02. A datagram is a 64-byte header, ciphertext, and a
16-byte GCM tag. All integers are unsigned big-endian; reject datagrams under 80
or over 1,500 bytes before decrypting.

```text
offset size field
0      4    magic: ASCII "GMA1"
4      1    version: 1
5      1    kind: 1 AUDIO, 2 PATH_CHALLENGE, 3 PATH_RESPONSE, 4 FEEDBACK
6      2    flags: 0 in v1
8      16   session_id: raw bytes decoded from control hex
24     4    stream_id
28     1    direction: 1 WIN_TO_MAC, 2 MAC_TO_WIN
29     3    reserved: 0
32     4    key_epoch: 1..4294967295
36     8    sequence: per-direction, per-epoch u64
44     8    media_timestamp: source frame, or 0 for path/feedback
52     4    payload_length: plaintext bytes excluding tag
56     8    reserved: 0
64     N    ciphertext of exactly payload_length bytes
64+N   16   AES-256-GCM tag
```

Header bytes 0..63, exactly as received, are AEAD AAD. The nonce is
`uint32_be(key_epoch) || uint64_be(sequence)`. AUDIO and FEEDBACK use the
directional `media_key`; path packets use that direction's `path_key`. Direction
must name the sender and match the authenticated peer's socket role. It is AAD, so
neither endpoint may rewrite it.

Each direction chooses a fresh CSPRNG u64 initial sequence after deriving an epoch
and increments it before every encryption attempt, including a failed send. It never
wraps, resets, persists, or reuses a value in that epoch. Rekey before 2^32 packets,
30 minutes, or sequence exhaustion through `stream.rekey` in document 03. Keep one
1024-sequence replay window per `(stream_id, direction, key_epoch)` and advance it
only after successful AEAD authentication. Drop duplicates and packets over 1023
behind the highest authenticated sequence.

Before AEAD, validate datagram atomicity (drop API-reported truncation), magic,
version, kind, flags, reserved bytes, authorized IP:port, session/stream/epoch,
direction, declared length, and replay eligibility. A failed tag is a silent drop.
Unknown or mismatched input creates no state, response, worker job, or log entry.

The receive loop first performs only fixed-size header and source-tuple classification.
It reserves at least 75 percent of packet-processing iterations and AEAD budget for
currently path-authorized tuples; unknown or mismatched tuples cannot consume that
reserve. Unknown/mismatched tuples together receive at most 128 datagrams or 128 KiB
per rolling second (burst 256/256 KiB), with 8 datagrams per source per second. An
authorized stream receives at most 500 datagrams per second; all authorized streams
together at most 2,000. A tuple is also capped at 300 datagrams or 360 KiB per
second (burst 600/720 KiB). Apply all limits before AEAD, including invalid-tag and
replayed packets, and schedule authorized streams fairly. Classification uses fixed
storage and never creates a tuple entry for an unknown packet.

## 2. Path validation

`transport.bind` commits the only candidate UDP tuple: TCP peer address plus the
UDP port supplied over authenticated control. An authorized `stream.open` enters `probing` and sends
a PATH_CHALLENGE in the Windows-to-Mac direction. Its plaintext is exactly one
fresh 96-bit CSPRNG value. The Mac returns the same 12 bytes in PATH_RESPONSE using
its Mac-to-Windows path key and a new sequence. It never echoes ciphertext, header,
or received sequence.

Send at most three challenges, one per second, and at most eight per stream per
minute. Retain at most three outstanding values for the five-second candidate
deadline. A matching authenticated response consumes its value, authorizes that
tuple for the stream and epoch for 30 seconds, and emits `event.path.validated`.
Unknown, expired, duplicate, or unmatched responses are dropped. Deadline failure
emits `event.path.failed`. Receiving a challenge never validates a path or starts
audio. While a stream is sending, Windows refreshes its authorized path no later
than 25 seconds after the prior successful response; a refresh failure stops the
stream before its 30-second authorization expires. Rekey requires a new challenge;
at most two paths exist during the five-
second old-epoch grace. Any other address/port change requires a new TCP session.

## 3. Payload rules

AUDIO has an active nonzero stream and epoch, Windows-to-Mac direction, and a
negotiated profile. PCM is interleaved signed 16-bit little-endian samples, exactly
`frames_per_packet * channels * 2` bytes: 960 bytes for the baseline 48 kHz,
stereo, 240-frame profile. Its timestamps are aligned to its first timestamp by
240 frames. Opus is one complete RFC 6716 packet, 1..1,128 bytes, decodes to 480
frames, and timestamps align by 480. The first timestamp may be any u64; whole-
packet gaps are permitted after sender queue drops. Reject nonaligned timestamps,
wrong lengths, codec, layout, stream, epoch, or direction before allocation/decode.

Send one packet per profile interval. On source overrun drop the oldest complete
block and advance timestamp. PCM underrun sends timestamped silence. Opus underrun
sends an encoded silent frame or reports a discontinuity and restarts. Never delay
stale samples to preserve transport sequence.

FEEDBACK has an active stream/epoch, Mac-to-Windows direction, zero timestamp, and
exactly this 32-byte plaintext:

```text
0  4 stream_id (equals header stream_id)
4  4 key_epoch (equals header key_epoch)
8  8 rendered_media_timestamp
16 4 target_buffer_us
20 4 buffered_us
24 2 loss_permille: 0..1000
26 2 late_permille: 0..1000
28 4 flags: bit 0 output_running, bit 1 output_underflow_since_last; others 0
```

Mac sends one feedback every 500 ms while active. Windows accepts one per stream
per 250 ms and ignores malformed, stale, inactive, or wrong-epoch feedback. It is
untrusted telemetry: it cannot allocate memory, change driver or security state,
alter format, or trigger an unsolicited control message. Missing feedback for three
seconds stops that stream with `REMOTE_OUTPUT_LOST` but leaves its session usable.

## 4. Receiver playout

After authenticated profile validation, insert by media timestamp. Keep the first
authenticated packet for a timestamp; drop packets over 120 ms late or 250 ms early.
The jitter buffer holds at most 300 ms, `ceil(300 ms / packet_interval)` packets,
or 64 KiB of encoded/PCM packet storage per stream, whichever comes first. This
supports the maximum 120 ms target plus reordering headroom for both v1 profiles.
An overflowing packet is dropped without moving playout. Start, stop, close, format
change, or excessive gap flushes jitter, decoder, and playout. Rekey retains buffered
audio and accepts both old and new epochs during the defined overlap; it does not
flush or reprime a healthy stream.

At each expected timestamp, render if present; otherwise conceal and advance without
waiting or rewind. PCM concealment is a 5 ms decay then silence; Opus uses PLC for
its 10 ms interval. Receive, AEAD, decode, insertion, and statistics run outside
the real-time callback. Its preallocated PCM ring holds at most 100 ms; underflow
emits silence and overflow drops oldest complete frames without blocking callback.

## 5. Mandatory tests

Publish and run byte-exact synthetic vectors for exporter inputs/output, both
directional media/path keys, header, nonce, plaintext, ciphertext, and tag. Test
altered AAD/ciphertext/tag, random initial sequences, failed sends, 1024-window
edges, duplicate/reordered packets, epoch transition, expired and altered path
responses, and every ingress budget. Fixtures contain no production identity, key,
session, or audio. Prove unauthenticated input cannot advance replay, validate a
path, allocate a stream buffer, refresh liveness, trigger a response, or reach
decode/playout.
