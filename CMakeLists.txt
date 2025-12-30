cmake_minimum_required(VERSION 3.10)
project(GardenSystem C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt
find_package(Qt6 COMPONENTS Widgets REQUIRED)

# Include directories
include_directories(
    ${PROJECT_SOURCE_DIR}
)

# Server sources
set(SERVER_SRC
    myServer.cpp
    protocol.c
)

# Client sources (Now includes Qt classes)
set(CLIENT_SRC
    main_qt.cpp
    MainWindow.cpp
    myClient.cpp
    protocol.c
)

# Build executables
add_executable(server ${SERVER_SRC})
target_link_libraries(server pthread)

# Client GUI
add_executable(client_gui ${CLIENT_SRC})
find_package(Qt6 COMPONENTS Charts REQUIRED)
target_link_libraries(client_gui Qt6::Widgets Qt6::Charts pthread)

