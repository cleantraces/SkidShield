cmake_minimum_required(VERSION 3.20)
project(SkidShield CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(skidshield-client src/client.cpp)
add_executable(skidshield-server src/server.cpp)

foreach(target skidshield-client skidshield-server)
    target_link_libraries(${target} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    if(WIN32)
        target_link_libraries(${target} PRIVATE ws2_32)
    endif()
endforeach()
