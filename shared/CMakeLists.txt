include(GNUInstallDirs)

add_library(gm_core STATIC
    core/gm_control.cpp
    core/gm_core.cpp
    core/gm_media.cpp)

add_library(GhostMedia::Core ALIAS gm_core)

set_target_properties(gm_core PROPERTIES
    EXPORT_NAME Core
    PUBLIC_HEADER include/ghostmedia/gm_core.h)

target_include_directories(gm_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_features(gm_core PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(gm_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(gm_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(GM_BUILD_TESTS)
    add_executable(gm_core_tests
        tests/gm_core_tests.cpp)

    target_link_libraries(gm_core_tests PRIVATE GhostMedia::Core)

    if(MSVC)
        target_compile_options(gm_core_tests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(gm_core_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME gm_core_tests COMMAND gm_core_tests)

    add_executable(gm_core_c_abi_tests
        tests/gm_core_c_abi_tests.c)

    target_link_libraries(gm_core_c_abi_tests PRIVATE GhostMedia::Core)
    set_target_properties(gm_core_c_abi_tests PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        LINKER_LANGUAGE CXX)

    if(MSVC)
        target_compile_options(gm_core_c_abi_tests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(gm_core_c_abi_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME gm_core_c_abi_tests COMMAND gm_core_c_abi_tests)
endif()

install(TARGETS gm_core
    EXPORT GhostMediaTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ghostmedia)

install(FILES include/module.modulemap
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT GhostMediaTargets
    NAMESPACE GhostMedia::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/GhostMedia)
