cmake_minimum_required(VERSION 3.18)

project(mbedtls-example VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_BUILD_TYPE DEBUG)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/deps/mbedtls)

find_package(Boost REQUIRED COMPONENTS url)

add_executable(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)
target_link_libraries(${PROJECT_NAME} PUBLIC mbedtls Boost::url)
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/mbedtls/include)
