# 06. Windows driver and service boundary

## Separation

The virtual audio driver is a WaveRT-style render endpoint. It is a kernel
component. Networking, mDNS, TCP, TLS, UDP, codecs, JSON, trust, UI, and remote
policy live only in the user-mode service. The driver contains no socket, DNS,
certificate, remote hostname, codec, or Mac dependency.

The driver must remain stable through service crash/restart, delayed service reads,
bad local requests, and all remote failures. It uses bounded nonblocking transfer
and discard; it does not retain unbounded kernel audio. Implementation should start
from [WaveRT miniport guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/developing-a-wavert-miniport-driver)
and [SYSVAD](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/sample-audio-drivers),
while treating both as driver starting points rather than protocol libraries.

## Local bridge contract

The following is the required v1 bridge ABI contract. It is a kernel/user-mode
trust boundary; it is not an optimization detail. `GhostMediaStreamSvc` is an
unprivileged Windows service with its own service SID. The device object ACL grants
bridge access only to `SYSTEM` and that service SID. Administrators may inspect
driver diagnostics through a separate read-only diagnostic interface but MUST NOT
obtain a bridge data handle. A process token is checked at `IRP_MJ_CREATE` against
the service SID, and the driver rejects remote, anonymous, impersonation, and
restricted tokens. The driver does not infer authority from executable path, PID, or
a client-supplied service name.

There is exactly one bridge data handle. `IOCTL_GM_BRIDGE_ATTACH` is accepted only
on a newly opened authorized handle and atomically installs a newly generated 128-bit
`bridge_epoch`. A second attach fails with `STATUS_DEVICE_BUSY`; only explicit close
or process-handle cleanup detaches it. The driver sets `FILE_DEVICE_SECURE_OPEN`,
uses `METHOD_BUFFERED` only for fixed-size control structures, and accepts no
pointer, handle, offset, or length supplied by the caller except fixed fields that
are range-checked before use. Unsupported IOCTLs fail closed.

`IOCTL_GM_BRIDGE_ATTACH` returns a fixed versioned descriptor: ABI major/minor,
epoch, immutable PCM format ID, block size, block count, ring byte size, and a
read-only section mapping plus a read-only notification event. The driver creates a
distinct section and event for each epoch, maps that section read-only into the
attached service process, and never reuses an old section for a later epoch. The
driver accepts no user-supplied shared-memory section or event. A service process
may read the ring and wait for the event outside real-time work; it cannot modify
producer indices, block payloads, or driver state. The driver remains the only
writer.

The mapped ring uses fixed, naturally aligned 64-bit commit words and Windows
interlocked primitives; generic cross-process C++ atomics are not the ABI. A block's
commit word is zero when empty, odd while the driver writes it, and an even monotonic
publication value when complete. The driver uses `InterlockedExchange64` to publish
the odd value, writes header and payload, executes `KeMemoryBarrier`, then publishes
the even value with `InterlockedExchange64`. The value never wraps during an epoch.
The service obtains a value with `InterlockedCompareExchange64`, accepts only a
nonzero even value, copies into private memory, executes a full acquire barrier, and
reads the commit word again. It accepts the copy only if both values match. A changed
epoch, odd/mismatched commit word, malformed descriptor, or torn/unavailable mapping
causes a block drop and bridge reopen; it never retries a kernel operation from an
audio callback.

`IRP_MJ_CLEANUP`, close, service death, and PnP removal atomically invalidate the
epoch, clear the reader, signal waiters, and return the ring to no-reader
overwrite/discard. All bridge IOCTLs verify both the opening process identity and
current epoch; an old file object is revoked on detach. An old mapping can expose
only its former epoch's contents because the driver never reuses its backing section
for a subsequent attachment.

The fixed ABI MUST provide:

| Property | Required behavior |
| --- | --- |
| Access | Only the GhostMedia service SID may open/attach a bridge data handle; access checks occur at open and attach |
| Data | Driver publishes render PCM blocks; service reads copies or read-only views |
| Capacity | Fixed, preallocated maximum of 100 ms normalized PCM; service freshness threshold is 50 ms |
| Driver producer | Never blocks, allocates, waits on user mode, or does network work |
| Overflow | Atomically drop oldest complete unread block and increment counters/timeline |
| No reader | Continue overwrite/discard and driver render-clock progression |
| Service crash | Closed handle returns driver to no-reader state |
| Service reconnect | New handle has a new bridge epoch; old blocks are ignored |

Choose and document one local PCM representation before implementation; it may
differ from network PCM. Every block includes format ID, frame count, monotonic
presentation marker, source frame index, bridge epoch, publication value, and flags.
The service validates descriptors as an untrusted boundary despite controlling the
expected client process. Block capacity, frame count, and format are immutable per
epoch; the driver does not parse a variable descriptor on the render path.

The endpoint remains a normal Windows device with zero bridge readers. It consumes
audio according to Windows endpoint rules and never reports a render fault solely
because remote streaming is unavailable.

## Service pipeline

The service reads blocks on a non-real-time worker, verifies epoch/format, converts
them, and places complete network blocks in a 40 ms bounded send queue with a 20 ms
freshness threshold. A separate
pacing worker consumes that queue. UDP backpressure, DNS, TLS stalls, codec delay,
logging, and UI work never run on a bridge reader or audio callback. Every handoff
has a fixed queue and metric.

On bridge epoch change, the service discards conversion/send queues and marks a
discontinuity. It never mixes epochs. It binds TCP and establishes the local bridge
before advertising mDNS. Shutdown stops starts, announces stops where possible,
withdraws discovery, closes its bridge handle, and leaves the driver independent.

## Security and failures

The service runs least-privileged. Its service SID is the only principal allowed on
the data interface; diagnostic access uses a distinct interface and contains no PCM
or mapping handles. Driver-created section/event handles are non-inheritable and
their DACLs do not grant new opens to other principals. An intentionally compromised
authorized service can still copy its readable PCM or duplicate an already granted
read handle, so containment of a compromised service is outside this bridge's trust
boundary; it is mitigated with least privilege, service hardening, and protected key
storage rather than a claim of kernel isolation. The same is true of a local
administrator with debugging/memory-inspection privilege; v1 does not claim to keep
rendered system audio secret from an administrator. The driver records the attached
process creation time and invalidates the epoch if it no longer matches the opening
process. Crash dumps and diagnostics exclude sample contents by default. The driver
preallocates memory outside its render path and logs only state transitions/rate-
limited counters.

| Failure | Driver | Service/network |
| --- | --- | --- |
| Mac disconnect | Continue endpoint/bridge discard | Stop stream and erase session keys |
| UDP blocked | Continue | Path failure; no TCP audio fallback |
| Service crash | No-reader state; continue | Restart policy; fresh sessions |
| Service behind | Drop old complete blocks | Record loss; discard stale send queue |
| Driver restart | Actual device state | Stop streams and report state event |
| TLS/feedback fail | No driver change | Close affected stream/session |

No network packet directly invokes driver work. Future input devices use the same
rule: a local device never depends on remote network completion.
