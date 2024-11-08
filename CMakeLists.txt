cmake_minimum_required(VERSION 3.29)
project(ISA)

set(CMAKE_CXX_STANDARD 14)

# Find the pcap library
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(ISA
        main.cpp
        printFunctions.cpp
        printFunctions.h
        dnsStructures.h
        helpFunctions.cpp
        helpFunctions.h
        parseFunctions.cpp
        parseFunctions.h
        processPacket.cpp
        processPacket.h
        filesOperations.cpp
        filesOperations.h)

# Link the pcap library
target_link_libraries(ISA PRIVATE ${PCAP_LIBRARIES})
