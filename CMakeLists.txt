cmake_minimum_required(VERSION 3.29)
project(ISA)

set(CMAKE_CXX_STANDARD 14)

add_executable(ISA
        main.cpp
        printFunctions.cpp
        printFunctions.h
        dnsStructures.h
        helpFunctions.cpp
        helpFunctions.h
        parseFunctions.cpp
        parseFunctions.h)
