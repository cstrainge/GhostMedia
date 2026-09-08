#include <ghostmedia/gm_core.h>

#include <iostream>

int main() {
    gm_core_version version{sizeof(gm_core_version), 0, 0, nullptr};
    const gm_status status = gm_get_version(&version);
    if (status != GM_OK) {
        std::cerr << "GhostMediaStreamSvc: core version query failed: "
                  << gm_status_string(status) << '\n';
        return 1;
    }

    std::cout << "GhostMediaStreamSvc scaffold\n"
              << "  ABI: " << version.abi_version << '\n'
              << "  protocol: " << version.protocol_major << '\n'
              << "  spec: " << version.spec_revision << '\n';
    return 0;
}
