cmake_minimum_required(VERSION 3.20)

if(CMAKE_HOST_WIN32 AND NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE FILEPATH "vcpkg toolchain file")
endif()

project(GhostMedia
    VERSION 0.1.0
    DESCRIPTION "GhostMedia shared protocol core and platform components"
    LANGUAGES C CXX)

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

if(GM_BUILD_WINDOWS AND WIN32)
    add_subdirectory(WinDevice)
endif()
