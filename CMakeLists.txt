cmake_minimum_required(VERSION 3.26)
project(vdm C)

set(CMAKE_C_STANDARD 90)

set(CMAKE_C_FLAGS "-Wall -Wextra -mwindows -fno-asynchronous-unwind-tables -fno-tree-loop-distribute-patterns -fno-stack-protector -mno-stack-arg-probe -nostdlib -static-libgcc -nostartfiles")
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_C_FLAGS_RELEASE "-s -O3")
set(CMAKE_C_FLAGS_MINSIZEREL "-s -O3")

add_executable(vdm main.c res.o)

target_link_libraries(vdm ntdll)
