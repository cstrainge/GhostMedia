# Apple Output Server

macOS/iOS output-server implementation home. This application will be built and
tested on Apple devices later. No Apple implementation is included yet.

The app advertises its output-server service, accepts the configured Windows control
client, receives UDP audio, and plays through the system-default output route according
to the [protocol design](../docs/README.md).

## First integration phase

Start with a Swift CLI harness that imports `GhostMediaCore` through the shared
Clang module map. The harness should validate the ABI with `gm_get_version`, parse
the v1 control fixtures through `gm_control_parse_message`, and use the media header,
nonce, and replay helpers without reimplementing protocol schema logic in Swift.
The detailed handoff for the Mac-side agent is in [INTEGRATION.md](INTEGRATION.md).

Build and test the shared core from the repository root on macOS:

```sh
cmake -S . -B out/build/macos -DGM_BUILD_WINDOWS=OFF -DGM_BUILD_TESTS=ON
cmake --build out/build/macos --target gm_core gm_core_tests gm_core_c_abi_tests
ctest --test-dir out/build/macos --output-on-failure
```
