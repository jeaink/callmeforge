cmake_minimum_required(VERSION 3.20)

project(forge VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_executable(forge
    src/main.cpp
    src/PEImage.cpp
    src/PEParser.cpp
    src/StringScanner.cpp
    src/CLI.cpp
)

target_include_directories(forge PRIVATE include)

if (WIN32)
    target_compile_definitions(forge PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
