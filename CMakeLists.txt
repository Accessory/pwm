cmake_minimum_required(VERSION 3.19)
project(pwm)

set(CMAKE_CXX_STANDARD 20)

include_directories($ENV{FLOW_ROOT})
include_directories($ENV{REPOSITORY_ROOT})
link_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(pwm pwm.cpp PasswordFile.h)
target_link_libraries(pwm argon2)

if (UNIX)
    include(GNUInstallDirs)

    install(TARGETS pwm
            RUNTIME DESTINATION bin
            )
endif ()