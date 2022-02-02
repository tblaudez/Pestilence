cmake_minimum_required(VERSION 3.16)
project(Pestilence ASM_NASM)

set(CMAKE_ASM_NASM_FLAGS_DEBUG "-g -Fdwarf")
set(CMAKE_ASM_NASM_OBJECT_FORMAT "elf64")
set(CMAKE_ASM_NASM_COMPILE_OBJECT "<CMAKE_ASM_NASM_COMPILER> <INCLUDES> <FLAGS> -f ${CMAKE_ASM_NASM_OBJECT_FORMAT} -o <OBJECT> <SOURCE>")

set(CMAKE_ASM_NASM_LINK_FLAGS "-nostdlib -fPIC -shared")
set(CMAKE_ASM_NASM_LINK_EXECUTABLE "ld <CMAKE_ASM_NASM_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")

set(SOURCES src/pestilence.asm)
set(HEADERS include/pestilence.inc)

add_executable(Pestilence ${SOURCES} ${HEADERS})
target_include_directories(Pestilence PRIVATE include)