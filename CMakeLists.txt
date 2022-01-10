cmake_minimum_required(VERSION 3.14)

include(FetchContent)



project(nmrpflash VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "-g -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "-g -Wall")

find_package(Boost REQUIRED)

FetchContent_Declare(GSL
    GIT_REPOSITORY "https://github.com/microsoft/GSL"
    GIT_TAG "v3.1.0"
)

FetchContent_MakeAvailable(GSL)

include_directories(
	${PROJECT_BINARY_DIR}
	"${PROJECT_SOURCE_DIR}/include"
	${Boost_INCLUDE_DIRS}
	"${GSL_SOURCE_DIR}/include"
)

add_executable(test src/test.cpp)
add_subdirectory(libnmrpflash)

target_link_libraries(test PUBLIC libnmrpflash -lpcap)
if (APPLE)
	target_link_libraries(test PUBLIC "-framework CoreFoundation")
endif()

target_include_directories(test PUBLIC
	"${PROJECT_BINARY_DIR}"
	"${PROJECT_SOURCE_DIR}/include"
	"${PROJECT_SOURCE_DIR}/libnmrpflash"
)
