# macOS user-experience contract

## Application form

GhostMedia ships as a standard signed macOS application. It has a normal app
window for detailed controls and a menu-bar icon for its everyday controls.

The menu-bar icon reflects connection state at a glance. Its dropdown is kept
deliberately small and has exactly three conceptual elements:

```text
GhostMedia
<connection status>

Pause Audio / Start Audio
Quit
```

Connection status is a concise, human-readable line, such as:

- `Ready to receive`
- `Connected to Windows PC`
- `Streaming from Windows PC`
- `Audio paused`
- `Connection lost`

`Pause Audio` suppresses audible output while preserving the active
connection/session when the protocol permits it. It changes to `Start Audio`
while audio is paused.

`Quit` stops output, cleanly closes any active session, withdraws discovery,
and exits the application.

The standard app window remains the place for pairing approvals, trusted-device
management, settings, and diagnostics. The menu-bar interface is not a second
settings surface.

An optional activity-log window may be added later for diagnostics and support.
It is not part of the initial macOS user interface or menu-bar scope.

## Implementation boundary

The macOS host composes a SwiftUI `MenuBarExtra` and normal `WindowGroup` from
the same `OutputServerService` snapshots. The menu sends user intent through
the service boundary; it must not own protocol state, sockets, Keychain records,
or real-time audio resources.
