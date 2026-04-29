cmake_minimum_required(VERSION 3.15)
project(dll_tracer LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- MSVC settings ----
if(MSVC)
    # Use the statically-linked runtime to avoid VCRT DLL dependency.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/utf-8 /W3 /WX-)
    # Suppress warnings from sqlite3 amalgamation
    add_compile_options($<$<COMPILE_LANGUAGE:C>:/W0>)
endif()

# ---- TitanEngine (bundled in deps/) ----
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(_TE_ARCH "Win32")
else()
    set(_TE_ARCH "x64")
endif()

set(_TE_DEPS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/deps/TitanEngine")
set(_TE_LIB "${_TE_DEPS_ROOT}/lib/${_TE_ARCH}/TitanEngine.lib")
set(_TE_DLL "${_TE_DEPS_ROOT}/bin/${_TE_ARCH}/TitanEngine.dll")

if(NOT EXISTS "${_TE_LIB}")
    message(FATAL_ERROR
        "TitanEngine.lib not found at: ${_TE_LIB}\n"
        "Expected layout: deps/TitanEngine/lib/${_TE_ARCH}/TitanEngine.lib")
endif()

# ---- SQLite3 (downloaded once by CMake FetchContent) ----
include(FetchContent)
FetchContent_Declare(
    sqlite3_src
    # SQLite 3.45.3 amalgamation (2024-03)
    URL https://www.sqlite.org/2024/sqlite-amalgamation-3450300.zip
)
FetchContent_MakeAvailable(sqlite3_src)

add_library(sqlite3_static STATIC ${sqlite3_src_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3_static PUBLIC ${sqlite3_src_SOURCE_DIR})
target_compile_definitions(sqlite3_static PRIVATE
    SQLITE_THREADSAFE=0         # single-threaded: no mutex overhead
    SQLITE_DEFAULT_MEMSTATUS=0  # skip memory accounting
    SQLITE_OMIT_LOAD_EXTENSION=1
)
# Suppress all warnings from the third-party amalgamation under MSVC
if(MSVC)
    target_compile_options(sqlite3_static PRIVATE /W0)
endif()

# ---- Main executable ----
add_executable(dll_tracer
    src/main.cpp
    src/pe_parser.cpp
    src/debugger.cpp
    src/tracer.cpp
    src/database.cpp
    src/space_calc.cpp
    src/validator.cpp
)

target_include_directories(dll_tracer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include   # TitanEngine.h client header
    ${CMAKE_CURRENT_SOURCE_DIR}/src       # peer headers (pe_parser.h, etc.)
)

target_link_libraries(dll_tracer PRIVATE
    sqlite3_static
    "${_TE_LIB}"
)

# ---- Copy TitanEngine.dll next to the built executable ----
add_custom_command(TARGET dll_tracer POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${_TE_DLL}"
        "$<TARGET_FILE_DIR:dll_tracer>"
    COMMENT "Copying TitanEngine.dll → output directory"
)
