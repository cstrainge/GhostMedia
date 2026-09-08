add_library(GhostMediaWinSecurity STATIC
    aes_gcm_provider.cpp)

target_include_directories(GhostMediaWinSecurity PUBLIC
    include)

target_link_libraries(GhostMediaWinSecurity PUBLIC
    GhostMedia::Core)

target_link_libraries(GhostMediaWinSecurity PRIVATE
    bcrypt)

target_compile_features(GhostMediaWinSecurity PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(GhostMediaWinSecurity PRIVATE /W4 /permissive-)
else()
    target_compile_options(GhostMediaWinSecurity PRIVATE -Wall -Wextra -Wpedantic)
endif()