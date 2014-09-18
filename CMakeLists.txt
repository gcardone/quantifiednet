project (quantifiednet CXX)

cmake_minimum_required (VERSION 2.8)

set(QUANTIFIEDNET_VERSION_MAJOR 0)
set(QUANTIFIEDNET_VERSION_MINOR 1)

file(GLOB SOURCES RELATIVE ${CMAKE_SOURCE_DIR} "src/*.cpp")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(Sqlite3 REQUIRED)
#find_package(PCAP REQUIRED)

configure_file (
    "${CMAKE_SOURCE_DIR}/src/config.h.in"
    "${CMAKE_BINARY_DIR}/config.h"
)


include_directories(${PROJECT_BINARY_DIR})
include_directories(${SQLITE3_INCLUDE_DIRS})
include_directories(${PCAP_INCLUDE_DIR})

#set(CMAKE_REQUIRED_LIBRARIES ${SQLITE3_LIBRARIES} ${PCAP_LIBRARY})
add_executable(quantifiednet ${SOURCES})
target_link_libraries(quantifiednet "-lsqlite3")
target_link_libraries(quantifiednet "-lpcap")

set_target_properties(quantifiednet PROPERTIES
	COMPILE_FLAGS "-O2 -Wall -pedantic -g -std=c++11"
)

