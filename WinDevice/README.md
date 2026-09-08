# WinDevice

Windows implementation home: persistent virtual audio driver, user-mode streaming
service, and Windows configuration support. No implementation is included yet.

Start with the [protocol design](../docs/README.md) and the
[driver/service boundary](../docs/06-windows-driver-boundary.md).

## Current scaffold

The initial Windows userspace target is `GhostMediaStreamSvc` under `service/`.
It links the shared `gm_core` static library and currently acts as a console
starter for the future service host. The WaveRT driver project is intentionally
not scaffolded yet; the protocol core and userspace vertical slice should build
and pass tests before WDK driver work begins.
