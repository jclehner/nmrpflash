cmake_minimum_required(VERSION 3.24)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_library(nmrpflash-gui OBJECT)

include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)

FetchContent_Declare(
	wxWidgets
	GIT_REPOSITORY https://github.com/wxWidgets/wxWidgets
	GIT_TAG v3.2.10
	GIT_PROGRESS TRUE
	GIT_SHALLOW TRUE
	EXCLUDE_FROM_ALL
#	FIND_PACKAGE_ARGS COMPONENTS core base xrc
)

set(BOOST_INCLUDE_LIBRARIES algorithm)
set(BOOST_ENABLE_CMAKE ON)
cmake_policy(SET CMP0167 NEW)

FetchContent_Declare(
	Boost
	URL https://github.com/boostorg/boost/releases/download/boost-1.90.0/boost-1.90.0-cmake.7z
	USES_TERMINAL_DOWNLOAD TRUE
	DOWNLOAD_NO_EXTRACT FALSE
	EXCLUDE_FROM_ALL
#	FIND_PACKAGE_ARGS COMPONENTS algorithm
)

find_package(wxWidgets COMPONENTS core base xrc)
if(wxWidgets_FOUND)
	target_link_libraries(nmrpflash-gui PUBLIC wxWidgets::wxWidgets)
	set(wxrc ${wxWidgets_wxrc_EXECUTABLE})
	set(wxrc_depends "")
else()
	set(wxBUILD_SHARED OFF)
	set(wxUSE_STL ON)
	# speed up `make all` builds by disabling unneccessary stuff
	set(wxUSE_WEBVIEW OFF)
	set(wxUSE_REGEX OFF)
	FetchContent_MakeAvailable(wxWidgets)
	target_link_libraries(nmrpflash-gui PUBLIC wx::core wx::base wx::xrc)
	set(wxrc $<TARGET_FILE:wxrc>)
	set(wxrc_depends "wxrc")
endif()

#cmake_policy(SET CMP0167 NEW)
#find_package(Boost)
#if(Boost_FOUND)
#	target_include_directories(nmrpflash-gui PRIVATE Boost::algorithm)
#else()
FetchContent_MakeAvailable(Boost)
target_link_libraries(nmrpflash-gui PRIVATE Boost::algorithm)
#endif()

set(xrc_files ${CMAKE_CURRENT_SOURCE_DIR}/resources.xrc)
set(resources_cpp ${CMAKE_CURRENT_BINARY_DIR}/Resources.cpp)

add_custom_command(
	OUTPUT ${resources_cpp}
	COMMAND ${wxrc} -c -o ${resources_cpp} ${xrc_files}
	DEPENDS ${wxrc_depends}
	DEPENDS ${xrc_files}
	VERBATIM
	COMMENT "Compiling XRC resources"
)

target_sources(nmrpflash-gui PRIVATE
	AppFrame.cpp
	AppFrameBase.cpp
	DumbConsoleTextCtrl.cpp
	PrivilegedProcess.cpp
	Main.cpp
	Util.cpp
	${resources_cpp}
)