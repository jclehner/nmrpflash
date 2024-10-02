cmake_minimum_required(VERSION 3.6)
set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64" CACHE STRING "" FORCE)

project(
	nmrpflash
	VERSION 0.9.25
	LANGUAGES C
)

set(PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR})
add_executable(nmrpflash main.c nmrp.c tftp.c util.c ethsock.c)
target_compile_definitions(nmrpflash PUBLIC -DNMRPFLASH_VERSION=\"${nmrpflash_VERSION}\")

if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	target_link_libraries(nmrpflash -lpcap "-framework CoreFoundation")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_link_libraries(nmrpflash -lwpcap -lPacket -liphlpapi -lws2_32 -ladvapi32)
	target_include_directories(nmrpflash ./Npcap/Include/)
	if (CMAKE_SIZE_OF_VOID_P EQUAL 4)
		target_link_directories(nmrpflash ./Npcap/Lib/)
	else()
		target_link_directories(nmrpflash ./Npcap/Lib/x64)
	endif()
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
	find_package(PkgConfig)
	pkg_check_modules(NLROUTE REQUIRED IMPORTED_TARGET libnl-route-3.0)
	target_link_libraries(nmrpflash PkgConfig::NLROUTE})
else()
	set(nmrpflash_LIBS -lpcap)
endif()
