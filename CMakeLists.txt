cmake_minimum_required(VERSION 3.16)
project(AirPlayReceiver CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-Wall -Wextra -O2)

# Dependencies
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

pkg_check_modules(AVAHI REQUIRED avahi-client)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${AVAHI_INCLUDE_DIRS}
)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/playfair)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/plist)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/tlv8)

file(GLOB_RECURSE SOURCES 
    "src/*.cpp"
    "src/*.c"
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE
    Threads::Threads
    OpenSSL::Crypto
    OpenSSL::SSL
    ${AVAHI_LIBRARIES}
    playfair
    plist
    tlv8
)

message(STATUS "Configured ${PROJECT_NAME} for Linux / Raspberry Pi target")
