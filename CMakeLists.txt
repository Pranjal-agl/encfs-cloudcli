cmake_minimum_required(VERSION 3.16)
project(encfs-cloudcli VERSION 2.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(ENCFS_WERROR   "Treat compiler warnings as errors" OFF)
option(ENCFS_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(ENCFS_E2E      "Register the FUSE end-to-end test (needs /dev/fuse and fusermount3)" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)
find_package(OpenSSL 1.1 REQUIRED)
find_package(Threads REQUIRED)

# Common warnings / hardening, applied to every target via this interface lib.
add_library(encfs_options INTERFACE)
target_compile_options(encfs_options INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wconversion
                       -Wno-sign-conversion)
target_compile_definitions(encfs_options INTERFACE ENCFS_VERSION="${PROJECT_VERSION}")
if(ENCFS_WERROR)
    target_compile_options(encfs_options INTERFACE -Werror)
endif()
if(ENCFS_SANITIZE)
    target_compile_options(encfs_options INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(encfs_options INTERFACE -fsanitize=address,undefined)
endif()

# Core library: everything except the FUSE front-end, shared by all binaries
# (previously each executable recompiled these sources).
add_library(encfs_core STATIC
    src/crypto.cpp
    src/util.cpp
    src/index.cpp
    src/file_codec.cpp
    src/key_setup.cpp
    src/cloudcli_wrapper.cpp
)
target_include_directories(encfs_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(encfs_core PUBLIC OpenSSL::Crypto Threads::Threads encfs_options)

add_executable(encrypted_cloudfs src/encrypted_cloudfs.cpp)
target_link_libraries(encrypted_cloudfs PRIVATE encfs_core PkgConfig::FUSE3)

add_executable(decrypt_by_name tools/decrypt_by_name.cpp)
target_link_libraries(decrypt_by_name PRIVATE encfs_core)

install(TARGETS encrypted_cloudfs decrypt_by_name RUNTIME DESTINATION bin)

# ── Tests ───────────────────────────────────────────────────────────────────
enable_testing()

add_executable(test_crypto tests/unit/test_crypto.cpp)
target_link_libraries(test_crypto PRIVATE encfs_core)
add_test(NAME test_crypto COMMAND test_crypto)

add_executable(test_index tests/unit/test_index.cpp)
target_link_libraries(test_index PRIVATE encfs_core)
add_test(NAME test_index COMMAND test_index)

add_executable(test_integration tests/integration/test_integration.cpp)
target_link_libraries(test_integration PRIVATE encfs_core)
target_compile_definitions(test_integration PRIVATE
    ENCFS_STUB_PATH="${CMAKE_CURRENT_SOURCE_DIR}/tools/cloudcli_stub")
add_test(NAME test_integration COMMAND test_integration)

if(ENCFS_E2E)
    add_test(NAME test_e2e_fuse
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/run_e2e.sh
                     $<TARGET_FILE:encrypted_cloudfs>
                     $<TARGET_FILE:decrypt_by_name>
                     ${CMAKE_CURRENT_SOURCE_DIR}/tools/cloudcli_stub)
    set_tests_properties(test_e2e_fuse PROPERTIES TIMEOUT 120)
endif()
