# 08. Future microphone and camera support

V1 reserves direction and message structure without claiming microphone or camera
support. A future version MUST negotiate each new kind explicitly and MUST NOT send
unknown media kinds through a v1 peer. A v1 peer rejects them as `UNSUPPORTED_PROFILE`.

## Microphone direction

The likely future flow is Mac physical microphone -> Mac service -> protected UDP
-> Windows user-mode service -> Windows virtual recording endpoint. It is a new
device/driver bridge and has independent format, permission, mute, echo-cancellation,
and clock rules. It must not feed received audio into the render driver or grant a
network peer arbitrary capture access by virtue of system-audio permission.

Required future control additions include a capability such as `audio_receive`, a
separate authorization permission such as `inject_microphone`, explicit selected
microphone identity/local consent, `stream.open` direction `mac_to_win`, and a
recording endpoint availability state. The reverse UDP key, replay window, and
feedback path already exist conceptually, but profile codes and packet semantics
need a versioned definition. Echo cancellation must have access to a defined local
reference and cannot assume end-to-end network timing is fixed.

## Camera direction

Virtual camera support is not audio with larger packets. It needs its own device
integration, capture/encode pipeline, frame timestamps, keyframe recovery, rate
control, loss strategy, privacy indicator, camera permission, and much larger
MTU/fragmentation or a different media transport. GMA/1's 1,200-byte packet ceiling
and no-fragment design are intentionally audio-specific.

A future camera protocol should derive separate exporter labels/keys and use a
different magic/version namespace, such as `GMV`, so an audio parser never accepts
video. It must negotiate codec profile, width, height, frame rate, bit rate,
keyframe request, and receiver capability over TCP. It must define what happens
when packets/layers are missing and how an untrusted remote sender cannot exhaust
decoder/GPU/driver resources. It must never expose the physical camera to a remote
peer without a local authorization model.

## Extension rules

Do not reuse reserved header fields, known kind values, JSON message meanings, or
exporter labels for experimental features. Allocate experimental values in a
separate explicitly enabled development range. A future major protocol version
changes the mDNS `pv`, TLS ALPN, control `v`, and media magic/version together;
there is no silent downgrade. Add wire fixtures and negative tests before enabling
a capability in a released client.
