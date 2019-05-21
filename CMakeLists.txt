cmake_minimum_required(VERSION 3.14)
project(zadanie2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-lboost_program_options -lboost_system -lboost_filesystem")

add_executable(netstore-client client.cpp connection.cpp)
add_executable(netstore-server server.cpp connection.cpp)
