cmake_minimum_required(VERSION 3.10)
project(GardenSystem C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# Include directories
include_directories(
    ${PROJECT_SOURCE_DIR}
)

# Server sources
set(SERVER_SRC
    myServer.cpp
    protocol.c
)

# Client sources
set(CLIENT_SRC
    myClient.cpp
    protocol.c
)

# Build executables
add_executable(server ${SERVER_SRC})
add_executable(client ${CLIENT_SRC})

# Link pthread for Linux
target_link_libraries(server pthread)
target_link_libraries(client pthread)
