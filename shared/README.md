# GhostMedia Shared Core

The shared core is a portable C++20 static library with a C ABI. Platform code owns
sockets, TLS, DNS-SD, threads, clocks, device APIs, key stores, and audio codecs;
the shared core owns deterministic wire parsing and byte layout helpers.

## Apple integration surface

Swift imports the public C ABI through the Clang module map at
`shared/include/module.modulemap`:

```swift
import GhostMediaCore
```

When testing from the repository root on macOS, build the static library and run the
C/C++ smoke tests before wiring it into the Apple output server:

```sh
cmake -S . -B out/build/macos -DGM_BUILD_WINDOWS=OFF -DGM_BUILD_TESTS=ON
cmake --build out/build/macos --target gm_core gm_core_tests gm_core_c_abi_tests
ctest --test-dir out/build/macos --output-on-failure
```

For a direct Swift CLI smoke, point Swift at the include directory and built library
directory:

```sh
swiftc -I shared/include -L out/build/macos/shared -lgm_core Sources/main.swift
```

The first Apple harness should call `gm_get_version`, feed control JSON through
`gm_control_parse_message`, and use the media header/nonce/replay helpers directly.
It should not duplicate JSON schema decisions in Swift.