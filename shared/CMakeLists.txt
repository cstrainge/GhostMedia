add_library(gm_core STATIC
    core/gm_core.cpp)

add_library(GhostMedia::Core ALIAS gm_core)

target_include_directories(gm_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include)

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
endif()
