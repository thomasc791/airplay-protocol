cmake_minimum_required(VERSION 3.16)

aux_source_directory(. playfair_src)

set(DIR_SRCS ${playfair_src})

add_library(playfair STATIC ${DIR_SRCS})

target_include_directories(playfair PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
