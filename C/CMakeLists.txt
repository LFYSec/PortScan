cmake_minimum_required (VERSION 2.8)

project (PS)

aux_source_directory(. DIR_SRCS)

add_definitions("-Wall -g")

add_executable(portscan ${DIR_SRCS})

target_link_libraries(portscan pthread)