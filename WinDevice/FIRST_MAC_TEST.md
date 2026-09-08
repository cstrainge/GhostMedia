# First Mac Interop Test

This is the Windows-side run card for the first pre-TLS control interop test with
the actual Mac harness. It verifies TCP framing and the v1 control handshake shape
up through `stream.open`; it does not prove TLS, AES-GCM, UDP media, or v1 transport
conformance.

## Build And Local Smoke

From the repository root on Windows:

```powershell
$cmake = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$ctest = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe"
& $cmake --build --preset windows-msvc
& $ctest --preset windows-msvc --output-on-failure
.\out\build\windows-msvc\WinDevice\tools\control_probe\Debug\GhostMediaWinControlProbe.exe --dry-run
```

Expected tests:

```text
gm_core_tests
gm_phase2_vectors_tests
gm_core_c_abi_tests
win_crypto_provider_tests
win_control_probe_dry_run
```

## Mac Harness Contract

The Mac harness listens on a manually chosen TCP port and uses the GhostMedia
4-byte big-endian length-prefixed JSON frame format. For this first test only, it
may run without TLS if the Windows probe is invoked with `--allow-plaintext`.

The Mac harness must reply to these request IDs:

- `id:1` `session.hello` -> `result.role:"apple-output-server"`, stable
  `server_id`, `session_id`, `boot_id`, UDP port, capabilities, and limits.
- `id:2` `transport.bind` -> `result.path_state:"bound"`.
- `id:3` `stream.open` -> `result.stream_id`, `key_epoch:1`, accepted PCM profile,
  `packet_interval_us:5000`, and `path_state:"probing"`.

## Windows Command

Use the Mac harness host, port, and test server ID:

```powershell
.\out\build\windows-msvc\WinDevice\tools\control_probe\Debug\GhostMediaWinControlProbe.exe --connect <mac-host> <port> --allow-plaintext --expect-server-id <server-id>
```

If the Mac harness has not made its server ID stable yet, omit `--expect-server-id`
for discovery only. The probe will print a warning and log the returned `server_id`.
Add the flag back before treating the test as a pass.

## Pass Criteria

The Windows output must include:

```text
sent session.hello
received session.hello result
sent transport.bind
received transport.bind result
sent stream.open
received stream.open result
control interop reached stream.open
```

The Mac side should report the three received request types in order:

```text
session.hello
transport.bind
stream.open
```

## Expected Failures

- Missing `--allow-plaintext`: the probe exits before connecting.
- Wrong `--expect-server-id`: the probe rejects the `session.hello` result.
- Old role or direction assumptions: `gm_core` rejects the frame.
- Any malformed result schema: the probe fails while parsing the received frame.

After this passes, the next Windows-side work is the conformant Ed25519 TLS/exporter
adapter and encrypted UDP sender. The shared media key, nonce, AAD, AES-GCM, replay,
and rekey vector lock is already available through the Phase 2 tests.