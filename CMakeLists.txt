cmake_minimum_required(VERSION 3.5)
project(codeinjector)

set(SRC_LIST
	main.c
	supported_ecus.c
	supported_ecus.h)

add_executable(${PROJECT_NAME} ${SRC_LIST})
target_link_libraries(${PROJECT_NAME} bfd dl)
