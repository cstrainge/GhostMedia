add_subdirectory(security)
add_subdirectory(service)
add_subdirectory(tools/control_probe)

if(GM_BUILD_TESTS)
	add_subdirectory(tests)
endif()
