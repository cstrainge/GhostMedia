cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE FILEPATH "vcpkg toolchain file")
endif()

project(GhostMedia
    VERSION 0.1.0
    DESCRIPTION "GhostMedia shared protocol core and platform components"
    LANGUAGES C CXX)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

if(DEFINED CMAKE_TOOLCHAIN_FILE)
    message(STATUS "CMake toolchain file: ${CMAKE_TOOLCHAIN_FILE}")
endif()

option(GM_BUILD_TESTS "Build GhostMedia tests" ON)
option(GM_BUILD_WINDOWS "Build Windows userspace components when on Windows" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(GM_BUILD_TESTS)
    enable_testing()
endif()

add_subdirectory(shared)
add_subdirectory(runtime)

if(GM_BUILD_WINDOWS AND WIN32)
    add_subdirectory(WinDevice)
endif()

configure_package_config_file(
    cmake/GhostMediaConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/GhostMediaConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/GhostMedia")

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/GhostMediaConfigVersion.cmake"
    COMPATIBILITY SameMajorVersion)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/GhostMediaConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/GhostMediaConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/GhostMedia")

install(FILES cmake/module.modulemap
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
