# Still WIP! Use the regular Makefile for now!

cmake_minimum_required(VERSION 3.6)
set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64" CACHE STRING "" FORCE)

project(nmrpflash)

if (NOT DEFINED NMRPFLASH_VERSION)
	find_package(Git)

	if(GIT_FOUND)
			execute_process(
				COMMAND ${GIT_EXECUTABLE} describe --always
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
				OUTPUT_VARIABLE GIT_VERSION
				OUTPUT_STRIP_TRAILING_WHITESPACE
			)
			string(SUBSTRING ${GIT_VERSION} 1 -1 GIT_VERSION)
			string(REGEX REPLACE "-g.*$" "" GIT_VERSION_CMAKE ${GIT_VERSION})
			string(REPLACE "-" "." GIT_VERSION_CMAKE ${GIT_VERSION_CMAKE})
			project(${CMAKE_PROJECT_NAME} VERSION ${GIT_VERSION_CMAKE})
			set(NMRPFLASH_VERSION ${GIT_VERSION})

	else()
		message(FATAL_ERROR "Git not found, and no NMRPFLASH_VERSION defined")
	endif()
else()
	project(${CMAKE_PROJECT_NAME} VERSION ${NMRPFLASH_VERSION})
endif()

set(PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR})
add_executable(nmrpflash main.c nmrp.c tftp.c util.c ethsock.c)
target_compile_definitions(nmrpflash PUBLIC -DNMRPFLASH_VERSION=\"${NMRPFLASH_VERSION}\")

if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	target_link_libraries(nmrpflash -lpcap "-framework CoreFoundation")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_sources(nmrpflash PRIVATE nmrpflash.rc)
	target_compile_definitions(nmrpflash PUBLIC -D_WIN32_WINNT=0x0600 -DWIN32_LEAN_AND_MEAN -D__USE_MINGW_ANSI_STDIO)
	target_link_libraries(nmrpflash -lwpcap -lPacket -liphlpapi -lws2_32 -ladvapi32)
	target_include_directories(nmrpflash PUBLIC ./Npcap/Include)
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		target_link_directories(nmrpflash PUBLIC ./Npcap/Lib/x64)
	else()
		target_link_directories(nmrpflash PUBLIC ./Npcap/Lib)
	endif()
else()
	find_package(PkgConfig)
	pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
	target_link_libraries(nmrpflash PkgConfig::PCAP)

	if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
		pkg_check_modules(NLROUTE REQUIRED IMPORTED_TARGET libnl-route-3.0)
		target_link_libraries(nmrpflash PkgConfig::NLROUTE)
	endif()
endif()
