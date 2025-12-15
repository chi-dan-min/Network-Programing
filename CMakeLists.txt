cmake_minimum_required(VERSION 3.10)
project(GardenSystem C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# =========================
# 1. Protocol object (compile 1 lần)
# =========================
add_library(protocol_obj OBJECT protocol.c)

target_include_directories(protocol_obj PUBLIC
    ${PROJECT_SOURCE_DIR}
)

# =========================
# 2. Server
# =========================
add_executable(server
    myServer.cpp
    $<TARGET_OBJECTS:protocol_obj>
)

target_link_libraries(server pthread)

# =========================
# 3. Shared library cho Python
# =========================
add_library(protocol SHARED
    $<TARGET_OBJECTS:protocol_obj>
)

set_target_properties(protocol PROPERTIES
    OUTPUT_NAME "protocol"
)

target_link_libraries(protocol pthread)
