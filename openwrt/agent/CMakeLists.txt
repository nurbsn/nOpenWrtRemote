cmake_minimum_required(VERSION 3.16)
project(nopenwrtremote_agent C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(NORT_BUILD_TESTS "Build C unit tests" ON)
set(SECP256K1_SOURCE_DIR "" CACHE PATH "Optional pre-unpacked bitcoin-core/secp256k1 source directory")

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDH ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_ECMULT_WINDOW_SIZE 4 CACHE STRING "" FORCE)
set(SECP256K1_ECMULT_GEN_KB 2 CACHE STRING "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

if(SECP256K1_SOURCE_DIR AND EXISTS "${SECP256K1_SOURCE_DIR}/CMakeLists.txt")
    add_subdirectory("${SECP256K1_SOURCE_DIR}" secp256k1_build EXCLUDE_FROM_ALL)
else()
    include(FetchContent)
    FetchContent_Declare(
        secp256k1
        URL https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.6.0.tar.gz
        URL_HASH SHA256=785bb98e7d6705c51c8dfa8ac3af6aa2ccfa3774714d51c0b9e28fac1146e9f1
    )
    FetchContent_MakeAvailable(secp256k1)
endif()

find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h REQUIRED)
find_library(MBEDTLS_LIB mbedtls REQUIRED)
find_library(MBEDX509_LIB mbedx509 REQUIRED)
find_library(MBEDCRYPTO_LIB mbedcrypto REQUIRED)

if(PKG_CONFIG_FOUND)
    pkg_check_modules(JSONC json-c)
endif()
if(NOT JSONC_FOUND)
    find_path(JSONC_INCLUDE_DIRS json-c/json.h REQUIRED)
    find_library(JSONC_LIBRARIES json-c REQUIRED)
endif()

add_library(nort_core STATIC
    src/crypto.c
    src/config.c
    src/framing.c
    src/ws.c
    src/tunnel.c
    src/nostr.c
    src/control.c
)

target_include_directories(nort_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MBEDTLS_INCLUDE_DIR}
    ${JSONC_INCLUDE_DIRS}
)

target_compile_options(nort_core PRIVATE
    -Wall -Wextra -Os -ffunction-sections -fdata-sections
)

target_link_libraries(nort_core PUBLIC
    secp256k1
    ${MBEDTLS_LIB}
    ${MBEDX509_LIB}
    ${MBEDCRYPTO_LIB}
    ${JSONC_LIBRARIES}
    Threads::Threads
)

add_executable(nopenwrtremote-agent src/main.c)
target_compile_options(nopenwrtremote-agent PRIVATE -Wall -Wextra -Os -ffunction-sections -fdata-sections)
target_link_libraries(nopenwrtremote-agent PRIVATE nort_core)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(nopenwrtremote-agent PRIVATE -Wl,--gc-sections)
endif()

install(TARGETS nopenwrtremote-agent RUNTIME DESTINATION bin)

if(NORT_BUILD_TESTS)
    enable_testing()
    add_executable(nort_tests tests/test_crypto.c)
    target_compile_options(nort_tests PRIVATE -Wall -Wextra)
    target_link_libraries(nort_tests PRIVATE nort_core)
    add_test(NAME nort_crypto_tests COMMAND nort_tests)
endif()
