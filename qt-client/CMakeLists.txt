cmake_minimum_required(VERSION 3.16)
project(ClientQt LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Concurrent)

add_executable(ClientQt
    main.cpp
    mainwindow.cpp
    clientservice.cpp
    myclient.cpp
    protocol.c
)

target_link_libraries(ClientQt Qt6::Widgets Qt6::Concurrent)
