cmake_minimum_required(VERSION 3.14)
project(zadanie2)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-lboost_program_options")

add_executable(netstore-client client.cpp)
add_executable(netstore-server server.cpp)
