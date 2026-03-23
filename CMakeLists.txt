cmake_minimum_required(VERSION 3.15)
project(encfs-cloudcli VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find required libraries
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)
pkg_check_modules(OPENSSL REQUIRED openssl)

# Include directories
include_directories(${FUSE3_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIRS})

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -DNDEBUG")

# Source files
set(SOURCES
    src/encrypted_cloudfs.cpp
    src/crypto.cpp
    src/index.cpp
    src/cloudcli_wrapper.cpp
)

# Executable
add_executable(encrypted_cloudfs ${SOURCES})
target_link_libraries(encrypted_cloudfs
    ${FUSE3_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    pthread
)

# Include directories for tools and tests
include_directories(${CMAKE_SOURCE_DIR}/src)

# Test executable
enable_testing()
add_executable(decrypt_by_name tools/decrypt_by_name.cpp src/crypto.cpp src/index.cpp src/cloudcli_wrapper.cpp)
target_link_libraries(decrypt_by_name
    ${OPENSSL_LIBRARIES}
    pthread
)

# Unit tests
add_executable(test_crypto tests/unit/test_crypto.cpp src/crypto.cpp)
target_link_libraries(test_crypto ${OPENSSL_LIBRARIES} pthread)
add_test(NAME test_crypto COMMAND test_crypto)

add_executable(test_index tests/unit/test_index.cpp src/index.cpp src/crypto.cpp)
target_link_libraries(test_index ${OPENSSL_LIBRARIES} pthread)
add_test(NAME test_index COMMAND test_index)

# Integration tests
add_executable(test_integration tests/integration/test_integration.cpp src/crypto.cpp src/index.cpp src/cloudcli_wrapper.cpp)
target_link_libraries(test_integration ${OPENSSL_LIBRARIES} pthread)
add_test(NAME test_integration COMMAND test_integration)

