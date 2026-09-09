add_executable(GhostMediaWinControlProbe
    main.cpp)

target_link_libraries(GhostMediaWinControlProbe
    PRIVATE
        GhostMedia::Core
        GhostMedia::Runtime)

target_compile_features(GhostMediaWinControlProbe PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(GhostMediaWinControlProbe PRIVATE /W4 /permissive-)
else()
    target_compile_options(GhostMediaWinControlProbe PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(GM_BUILD_TESTS)
    add_test(NAME win_control_probe_dry_run COMMAND GhostMediaWinControlProbe --dry-run)
endif()