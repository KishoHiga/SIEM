cmake_minimum_required(VERSION 3.16)
project(SentinelCore VERSION 0.6.0 LANGUAGES CXX)

# Весь код — свой. Зависимости: только стандартная библиотека C++ и API ОС.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(SENTINEL_SANITIZE "Сборка с AddressSanitizer/UBSan (для отладки)" OFF)
option(SENTINEL_WITH_OPENSSL "Шифрование (HTTPS) через системный OpenSSL — единственная сторонняя библиотека" ON)

if(MSVC)
  add_compile_options(/W4 /utf-8 /permissive-)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  add_compile_options(-Wall -Wextra -Wshadow -Wno-unused-parameter)
  if(SENTINEL_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
  endif()
endif()

file(GLOB SENTINEL_LIB_SOURCES CONFIGURE_DEPENDS
  src/core/*.cpp
  src/regex/*.cpp
  src/parse/*.cpp
  src/detect/*.cpp
  src/store/*.cpp
  src/net/*.cpp
  src/server/*.cpp
  src/agent/*.cpp
  src/enrich/*.cpp
)
list(FILTER SENTINEL_LIB_SOURCES EXCLUDE REGEX ".*/(server|agent)/main\\.cpp$")

add_library(sentinel_lib STATIC ${SENTINEL_LIB_SOURCES})
target_include_directories(sentinel_lib PUBLIC src)

find_package(Threads REQUIRED)
target_link_libraries(sentinel_lib PUBLIC Threads::Threads)
if(WIN32)
  target_link_libraries(sentinel_lib PUBLIC ws2_32 wevtapi)
endif()

if(SENTINEL_WITH_OPENSSL)
  # macOS: OpenSSL ставится через Homebrew (brew install openssl@3)
  if(APPLE AND NOT OPENSSL_ROOT_DIR)
    foreach(p /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3)
      if(EXISTS ${p})
        set(OPENSSL_ROOT_DIR ${p})
      endif()
    endforeach()
  endif()
  find_package(OpenSSL)
  if(OPENSSL_FOUND)
    target_compile_definitions(sentinel_lib PUBLIC SENTINEL_HAVE_OPENSSL=1)
    target_link_libraries(sentinel_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "SentinelCore: HTTPS включён (OpenSSL ${OPENSSL_VERSION})")
  else()
    message(WARNING "SentinelCore: OpenSSL не найден — сборка БЕЗ HTTPS. "
                    "Linux: sudo apt install libssl-dev; macOS: brew install openssl@3")
  endif()
endif()

add_executable(sentinel-server src/server/main.cpp)
target_link_libraries(sentinel-server PRIVATE sentinel_lib)

add_executable(sentinel-agent src/agent/main.cpp)
target_link_libraries(sentinel-agent PRIVATE sentinel_lib)

add_executable(sentinel-bench tools/bench.cpp)
target_link_libraries(sentinel-bench PRIVATE sentinel_lib)

file(GLOB SENTINEL_TEST_SOURCES CONFIGURE_DEPENDS tests/*.cpp)
add_executable(sentinel-tests ${SENTINEL_TEST_SOURCES})
target_link_libraries(sentinel-tests PRIVATE sentinel_lib)
target_compile_definitions(sentinel-tests PRIVATE SENTINEL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

enable_testing()
add_test(NAME unit COMMAND sentinel-tests)
