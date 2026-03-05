# Still WIP! Use the regular Makefile for now!

cmake_minimum_required(VERSION 3.24)

if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
	message(FATAL_ERROR "In-source builds are not allowed")
endif()

option(NMRPFLASH_BUILD_GUI "Build with GUI support" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

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

# for all targets
add_compile_definitions(NMRPFLASH_VERSION=\"${NMRPFLASH_VERSION}\")
add_compile_options(-Wall)

add_executable(nmrpflash
	main.c
	nmrp.c
	tftp.c
	util.c
	ethsock.c
)

add_executable(t_tftp EXCLUDE_FROM_ALL
	t_tftp.c
	nmrp.c
	tftp.c
	util.c
	ethsock.c
)

add_executable(fuzz EXCLUDE_FROM_ALL
	tftp.c
	util.c
	nmrp.c
	fuzz.c
)
target_compile_definitions(fuzz PRIVATE NMRPFLASH_FUZZ)

if (NMRPFLASH_BUILD_GUI)
	add_subdirectory(gui)
	add_compile_definitions(NMRPFLASH_GUI=1)
	message("Building GUI too!")
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	target_link_libraries(nmrpflash -lpcap "-framework CoreFoundation -framework SystemConfiguration")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_sources(nmrpflash PRIVATE nmrpflash.rc)
	add_compile_definitions(_WIN32_WINNT=0x0600 WIN32_LEAN_AND_MEAN __USE_MINGW_ANSI_STDIO)
	link_libraries(-lwpcap -lPacket -liphlpapi -lws2_32 -ladvapi32)

	include_directories(3rdparty/Npcap/Include)
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		link_directories(3rdparty/Npcap/Lib/x64)
	else()
		link_directories(3rdparty/Npcap/Lib)
	endif()
else()
	find_package(PkgConfig)
	pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
	target_link_libraries(nmrpflash PRIVATE PkgConfig::PCAP)

	if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
		pkg_check_modules(NLROUTE REQUIRED IMPORTED_TARGET libnl-route-3.0)
		target_link_libraries(nmrpflash PRIVATE PkgConfig::NLROUTE)
		target_link_libraries(t_tftp PRIVATE PkgConfig::NLROUTE)
		target_include_directories(nmrpflash PRIVATE PkgConfig::NLROUTE)
		target_include_directories(t_tftp PRIVATE PkgConfig::NLROUTE)
	endif()
endif()


if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_sources(nmrpflash PRIVATE nmrpflash.rc)
endif()
