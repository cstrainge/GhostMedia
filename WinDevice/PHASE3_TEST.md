# Phase 3 secure two-host test

This command-line fixture demonstrates the first secure Windows-to-Apple media
slice: pinned mutual TLS 1.3 control, TLS-exporter media keys, AES-256-GCM UDP
path validation, and eight paced 48 kHz stereo PCM packets delivered to the
Apple deterministic discard sink.

It uses deterministic identities compiled into the explicit `--phase3-test`
mode. They are test fixtures only. They are never loaded by the application,
the service, or the plaintext probe, and must not be used outside a private lab.

## Apple output server

Build the current checkout on the Apple host, then start one listener:

```sh
xcrun swift run GhostMediaAppleHarness --listen 51837 --phase3-test
```

Wait for the listener message before starting Windows. The harness accepts one
connection and exits after receiving the synthetic packets. It binds UDP port
`51838`; allow both TCP `51837` and UDP `51838` on the private test network.

## Windows control client and media sender

From the repository root:

```powershell
.\WinDevice\Run-Phase3Test.ps1 -AppleIPv4 <apple-ipv4>
```

The wrapper verifies that the built probe exists and the requested UDP port is
available, then launches the test directly. It deliberately does not make a TCP
readiness connection because the Apple harness accepts one connection only. The
Windows process binds UDP port `49152` by default. If it is unavailable, choose
another free port with `-WindowsUDPPort`; that selected port is authenticated
inside the TLS control session before the Apple harness accepts media.

## Pass criteria

Windows reports `mutual TLS 1.3 established`, `protected UDP path validated`,
and `sent 8 encrypted synthetic PCM packets`. Apple reports the protected UDP
path and `discarded 8 authenticated PCM packets`.

The fixture currently covers IPv4 and a manually configured Apple server. It
does not yet cover DNS-SD, interface loss, feedback, rekey, fault injection, or
Apple audible output.
