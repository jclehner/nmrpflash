cmake_minimum_required(VERSION 3.24)

cmake_policy(SET CMP0167 NEW)

enable_language(CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_library(nmrpflash-gui OBJECT)

FetchContent_Declare(
	wxWidgets
	URL https://github.com/wxWidgets/wxWidgets/releases/download/v3.2.10/wxWidgets-3.2.10.7z
	URL_HASH SHA256=62bd697e202ea013526b70dc57cb1dbe53e6b09af9294c2018e6d62625f42160
	USES_TERMINAL_DOWNLOAD TRUE
	DOWNLOAD_NO_EXTRACT FALSE
	EXCLUDE_FROM_ALL
)

FetchContent_Declare(GSL
    GIT_REPOSITORY "https://github.com/microsoft/GSL"
    GIT_TAG "v4.2.1"
    GIT_SHALLOW ON
	EXCLUDE_FROM_ALL
)

FetchContent_MakeAvailable(GSL)
target_link_libraries(nmrpflash-gui PRIVATE Microsoft.GSL::GSL)

find_package(wxWidgets COMPONENTS core base xrc)
if(wxWidgets_FOUND)
	target_link_libraries(nmrpflash-gui PUBLIC wxWidgets::wxWidgets)
	set(wxrc ${wxWidgets_wxrc_EXECUTABLE})
	set(wxrc_depends "")
else()
	set(wxBUILD_SHARED OFF)
	set(wxUSE_STL ON)

	# speed up builds, and shrink library a bit
	set(wxUSE_WEBVIEW OFF)
	set(wxUSE_REGEX OFF)
	set(wxUSE_OPENGL OFF)
	set(wxUSE_LIBJPEG OFF)
	set(wxUSE_LIBWEBP OFF)
	set(wxUSE_LIBTIFF OFF)

	FetchContent_MakeAvailable(wxWidgets)
	target_link_libraries(nmrpflash-gui PUBLIC wx::core wx::base wx::xrc)
	set(wxrc $<TARGET_FILE:wxrc>)
	set(wxrc_depends "wxrc")
endif()

set(BOOST_INCLUDE_LIBRARIES algorithm)
set(BOOST_ENABLE_CMAKE ON)

FetchContent_Declare(
	Boost
	URL https://github.com/boostorg/boost/releases/download/boost-1.90.0/boost-1.90.0-cmake.7z
	URL_HASH SHA256=218e74c4aa362a994b7b7a23b2920f455a00205c656405fcf262cf60b8871921
	USES_TERMINAL_DOWNLOAD TRUE
	DOWNLOAD_NO_EXTRACT FALSE
	EXCLUDE_FROM_ALL
	FIND_PACKAGE_ARGS COMPONENTS algorithm
)
FetchContent_MakeAvailable(Boost)

if (Boost_FOUND)
	target_link_libraries(nmrpflash-gui PRIVATE Boost::boost)
else()
	target_link_libraries(nmrpflash-gui PRIVATE Boost::algorithm)
endif()

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
	App.cpp
	Util.cpp
	${resources_cpp}
)
