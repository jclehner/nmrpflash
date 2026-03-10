cmake_minimum_required(VERSION 3.24)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(nmrpflash-gui OBJECT)

include(FetchContent)
set(FETCHCONTENT_QUIET False)

FetchContent_Declare(
	wxWidgets
	GIT_REPOSITORY https://github.com/wxWidgets/wxWidgets
	GIT_TAG v3.2.10
	GIT_PROGRESS True
)

FetchContent_Declare(
	BoostAlgorithm
	GIT_REPOSITORY https://github.com/boostorg/algorithm
	GIT_TAG boost-1.90.0
	GIT_PROGRESS True
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
	set(wxUSE_ADV OFF)
	set(wxUSE_AUI OFF)
	set(wxUSE_GL OFF)
	set(wxUSE_LIBJPEG OFF)
	set(wxUSE_LIBTIFF OFF)
	set(wxUSE_MEDIA OFF)
	set(wxUSE_NET OFF)
	set(wxUSE_PROPGRID OFF)
	set(wxUSE_QA OFF)
	set(wxUSE_REGEX OFF)
	set(wxUSE_RIBBON OFF)
	set(wxUSE_RICHTEXT OFF)
	set(wxUSE_SCINTILLA OFF)
	set(wxUSE_STC OFF)
	set(wxUSE_WEBVIEW OFF)
	FetchContent_MakeAvailable(wxWidgets)
	target_link_libraries(nmrpflash-gui PUBLIC wx::core wx::base wx::xrc)
	set(wxrc $<TARGET_FILE:wxrc>)
	set(wxrc_depends "wxrc")
endif()

cmake_policy(SET CMP0167 NEW)
find_package(Boost)
if(Boost_FOUND)
	target_include_directories(nmrpflash-gui PRIVATE Boost::headers)
else()
	FetchContent_MakeAvailable(BoostAlgorithm)
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
	Main.cpp
	Util.cpp
	${resources_cpp}
)