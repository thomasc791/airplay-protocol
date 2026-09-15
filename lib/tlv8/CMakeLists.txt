cmake_minimum_required(VERSION 3.16)

aux_source_directory(. tlv8_src)

set(DIR_SRCS ${tlv8_src})

add_library(tlv8 STATIC ${DIR_SRCS})

target_include_directories(tlv8 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
