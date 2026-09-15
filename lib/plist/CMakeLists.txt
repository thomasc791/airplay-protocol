cmake_minimum_required(VERSION 3.16)

aux_source_directory(. plist_src)

set(DIR_SRCS ${plist_src})

add_library(plist STATIC ${DIR_SRCS})

target_include_directories(plist PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
