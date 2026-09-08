cmake_minimum_required(VERSION 3.20)

project(GhostMedia
    VERSION 0.1.0
    DESCRIPTION "GhostMedia shared protocol core and platform components"
    LANGUAGES CXX)

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
