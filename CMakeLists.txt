cmake_minimum_required(VERSION 3.16)
project(AirPlayReceiver CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-Wall -Wextra -O2)

# Dependencies
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ALSA REQUIRED)

pkg_check_modules(AVAHI REQUIRED avahi-client)
pkg_check_modules(FFMPEG REQUIRED libavcodec libavutil libswresample)
pkg_check_modules(NetworkManager REQUIRED IMPORTED_TARGET libnm glib-2.0 gobject-2.0)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${AVAHI_INCLUDE_DIRS}
    ${FFMPEG_INCLUDE_DIRS}
    ${ALSA_INCLUDE_DIRS}
    ${LIBNM_INCLUDE_DIRS}
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
    ${FFMPEG_LIBRARIES}
    ${ALSA_LIBRARIES}
    PkgConfig::NetworkManager
    playfair
    plist
    tlv8
)

message(STATUS "Configured ${PROJECT_NAME} for Linux / Raspberry Pi target")
