include(GNUInstallDirs)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)

add_library(GhostMediaRuntime STATIC
    core/aes_gcm_provider.cpp
    core/certificate_profile.cpp
    core/gm_runtime.cpp
    core/identity_provider.cpp
    core/socket_provider.cpp
    core/tls_provider.cpp)

add_library(GhostMedia::Runtime ALIAS GhostMediaRuntime)

set_target_properties(GhostMediaRuntime PROPERTIES EXPORT_NAME Runtime)

target_include_directories(GhostMediaRuntime
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(GhostMediaRuntime
    PUBLIC
        GhostMedia::Core
    PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL)

if(WIN32)
    target_link_libraries(GhostMediaRuntime PRIVATE ws2_32)
endif()

target_compile_features(GhostMediaRuntime PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(GhostMediaRuntime PRIVATE /W4 /permissive-)
else()
    target_compile_options(GhostMediaRuntime PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(GM_BUILD_TESTS)
    add_executable(GhostMediaRuntimeSecurityTests
        tests/runtime_security_tests.cpp)

    target_link_libraries(GhostMediaRuntimeSecurityTests PRIVATE
        GhostMediaRuntime
        OpenSSL::Crypto
        OpenSSL::SSL)

    target_compile_features(GhostMediaRuntimeSecurityTests PRIVATE cxx_std_20)

    if(MSVC)
        target_compile_options(GhostMediaRuntimeSecurityTests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(GhostMediaRuntimeSecurityTests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME runtime_security_tests COMMAND GhostMediaRuntimeSecurityTests)
endif()

install(TARGETS GhostMediaRuntime
    EXPORT GhostMediaTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(DIRECTORY include/ghostmedia/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ghostmedia)
