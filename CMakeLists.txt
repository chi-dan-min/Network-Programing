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

set(CLIENT_API_SRC
    client_api.cpp    
)

# Build executables
add_executable(server ${SERVER_SRC})

# Tạo thư viện chia sẻ client_core
add_library(client_core SHARED ${CLIENT_API_SRC})
set_target_properties(client_core PROPERTIES OUTPUT_NAME "client_core") 

# Link pthread cho cả Server và API
target_link_libraries(server pthread)
target_link_libraries(client_core pthread)