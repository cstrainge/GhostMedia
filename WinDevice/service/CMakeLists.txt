add_executable(GhostMediaStreamSvc
    main.cpp)

target_link_libraries(GhostMediaStreamSvc PRIVATE GhostMedia::Core)
target_compile_features(GhostMediaStreamSvc PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(GhostMediaStreamSvc PRIVATE /W4 /permissive-)
else()
    target_compile_options(GhostMediaStreamSvc PRIVATE -Wall -Wextra -Wpedantic)
endif()
