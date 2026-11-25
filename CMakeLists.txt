cmake_minimum_required(VERSION 3.20)
project(keel_crypto VERSION 0.1.0 LANGUAGES CXX)

option(KEEL_CRYPTO_NO_EXCEPTIONS_RTTI "Compile keel_crypto without C++ exceptions and RTTI" OFF)
option(KEEL_CRYPTO_BUILD_TESTS "Build keel_crypto unit tests and header purity checks" ${PROJECT_IS_TOP_LEVEL})

if(NOT TARGET keel::keel)
    find_package(keel QUIET CONFIG)
endif()
if(NOT TARGET keel::keel)
    include(FetchContent)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../keel/CMakeLists.txt" AND NOT DEFINED FETCHCONTENT_SOURCE_DIR_KEEL)
        set(FETCHCONTENT_SOURCE_DIR_KEEL "${CMAKE_CURRENT_SOURCE_DIR}/../keel" CACHE PATH "Local keel checkout")
    endif()
    if(KEEL_CRYPTO_NO_EXCEPTIONS_RTTI)
        set(KEEL_NO_EXCEPTIONS_RTTI ON CACHE BOOL "" FORCE)
    endif()
    FetchContent_Declare(
        keel
        GIT_REPOSITORY https://github.com/keelcpp/keel.git
        GIT_TAG        5d80fa7d6984e7325fc8d5317c5db13830381429
    )
    FetchContent_MakeAvailable(keel)
endif()

add_library(keel_crypto STATIC
    src/ct.cpp
    src/digest.cpp
    src/hmac.cpp
    src/kdf.cpp
)
add_library(keel::crypto ALIAS keel_crypto)

target_link_libraries(keel_crypto PUBLIC keel::keel)

target_compile_features(keel_crypto PUBLIC cxx_std_20)
set_target_properties(keel_crypto PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(keel_crypto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(MSVC)
    target_compile_options(keel_crypto PRIVATE /W4 /utf-8 /MP)
    if(KEEL_CRYPTO_NO_EXCEPTIONS_RTTI)
        string(REGEX REPLACE "/EH[a-z]+" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        string(REGEX REPLACE "/GR" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        target_compile_options(keel_crypto PUBLIC /EHs-c- /GR-)
        target_compile_definitions(keel_crypto PUBLIC _HAS_EXCEPTIONS=0)
    endif()
else()
    target_compile_options(keel_crypto PRIVATE -Wall -Wextra -Wpedantic)
    if(KEEL_CRYPTO_NO_EXCEPTIONS_RTTI)
        target_compile_options(keel_crypto PUBLIC -fno-exceptions -fno-rtti)
    endif()
endif()

if(COMMAND keel_enforce_guidelines)
    keel_enforce_guidelines(keel_crypto
        SCOPE ALL
        BAN_RAW_INTS ALL
        BAN_RAW_FLOATS ALL
        HEADERS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include"
        STANDALONE_HEADERS ${KEEL_CRYPTO_BUILD_TESTS}
        TEST_NAME test_guidelines_headers
        WARNINGS OFF
    )
endif()

include(CMakePackageConfigHelpers)
install(TARGETS keel_crypto EXPORT keel_cryptoTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/keel DESTINATION include)
install(EXPORT keel_cryptoTargets
    FILE keel_cryptoTargets.cmake
    NAMESPACE keel::
    DESTINATION lib/cmake/keel_crypto
)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/keel_cryptoConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/keel_cryptoConfig.cmake"
    INSTALL_DESTINATION lib/cmake/keel_crypto
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/keel_cryptoConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMinorVersion
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/keel_cryptoConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/keel_cryptoConfigVersion.cmake"
    DESTINATION lib/cmake/keel_crypto
)

if(KEEL_CRYPTO_BUILD_TESTS)
    enable_testing()

    add_executable(test_crypto tests/test_crypto.cpp)
    target_link_libraries(test_crypto PRIVATE keel::crypto)
    if(MSVC)
        target_compile_options(test_crypto PRIVATE /W4 /utf-8 /MP)
    else()
        target_compile_options(test_crypto PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME test_crypto COMMAND test_crypto)

    get_target_property(KEEL_CORE_INC_DIRS keel::keel INTERFACE_INCLUDE_DIRECTORIES)
    set(KEEL_DEP_INC_CLEAN "")
    foreach(IDIR IN LISTS KEEL_CORE_INC_DIRS)
        string(REGEX REPLACE "\\$<BUILD_INTERFACE:([^>]+)>" "\\1" IDIR_STRIPPED "${IDIR}")
        if(NOT IDIR_STRIPPED MATCHES "\\$<INSTALL_INTERFACE:" AND EXISTS "${IDIR_STRIPPED}")
            list(APPEND KEEL_DEP_INC_CLEAN "${IDIR_STRIPPED}")
        endif()
    endforeach()
    list(REMOVE_DUPLICATES KEEL_DEP_INC_CLEAN)
    string(REPLACE ";" "|" KEEL_DEP_INC_JOINED "${KEEL_DEP_INC_CLEAN}")
    string(REPLACE ";" "|" KEEL_STD_INC_JOINED "${CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES}")

    add_test(
        NAME test_header_purity
        COMMAND ${CMAKE_COMMAND}
            "-DKEEL_INCLUDE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/include"
            "-DKEEL_DEP_INC_DIRS=${KEEL_DEP_INC_JOINED}"
            "-DCOMPILER_PATH=${CMAKE_CXX_COMPILER}"
            "-DCOMPILER_ID=${CMAKE_CXX_COMPILER_ID}"
            "-DSTD_INC_DIRS=${KEEL_STD_INC_JOINED}"
            "-DCMAKE_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CheckHeaderPurity.cmake"
    )
endif()
