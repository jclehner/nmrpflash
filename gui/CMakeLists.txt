cmake_minimum_required(VERSION 3.24)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(wxWidgets COMPONENTS core base xrc)
if(wxWidgets_FOUND)
	target_link_libraries(nmrpflash PRIVATE wxWidgets::wxWidgets)
	set(wxrc ${wxWidgets_wxrc_EXECUTABLE})
	set(wxrc_depends "")
else()
	set(wxBUILD_SHARED OFF)
	add_subdirectory(3rdparty/wxWidgets)
	target_link_libraries(nmrpflash PRIVATE wx::core wx::base wx::xrc)
	set(wxrc $<TARGET_FILE:wxrc>)
	set(wxrc_depends "wxrc")
endif()

cmake_policy(SET CMP0167 NEW)
find_package(Boost)
if(Boost_FOUND)
	target_include_directories(nmrpflash PRIVATE Boost::headers)
endif()

set(xrc_files ${CMAKE_CURRENT_SOURCE_DIR}/resources.xrc)
set(resources_cpp ${CMAKE_CURRENT_BINARY_DIR}/Resources.cpp)

add_custom_command(
	OUTPUT ${resources_cpp}
	COMMAND ${wxrc} -c -o ${resources_cpp} ${xrc_files}
	DEPENDS ${wxrc_depends}
	DEPENDS ${xrc_files}
	COMMENT "Compiling XRC resources"
)

target_sources(nmrpflash PRIVATE
	AppFrame.cpp
	AppFrameBase.cpp
	DumbConsoleTextCtrl.cpp
	PrivilegedProcess.cpp
	Main.cpp
	Util.cpp
	${resources_cpp}
)