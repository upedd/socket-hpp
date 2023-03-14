cmake_minimum_required(VERSION 3.24)
project(socket-hpp)

set(CMAKE_CXX_STANDARD 23)

add_executable(example_server socket.hpp examples/server.cpp)
add_executable(example_talker socket.hpp examples/talker.cpp)
add_executable(example_listener socket.hpp examples/listener.cpp)
add_executable(example_client socket.hpp examples/client.cpp)
