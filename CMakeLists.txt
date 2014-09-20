project (quantifiednet CXX)

cmake_minimum_required (VERSION 2.8)

file(GLOB SOURCES RELATIVE ${CMAKE_SOURCE_DIR} "src/*.cpp")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(Sqlite3 REQUIRED)
find_package(PCAP REQUIRED)

include_directories(${PROJECT_BINARY_DIR})
include_directories(${SQLITE3_INCLUDE_DIRS})
include_directories(${PCAP_INCLUDE_DIR})

set(CMAKE_REQUIRED_LIBRARIES ${SQLITE3_LIBRARIES} ${PCAP_LIBRARIES})
add_executable(quantifiednet ${SOURCES})
target_link_libraries(quantifiednet "-lsqlite3")
target_link_libraries(quantifiednet "-lpcap")

set_target_properties(quantifiednet PROPERTIES
	COMPILE_FLAGS "-O2 -Wall -pedantic -std=c++11"
)
