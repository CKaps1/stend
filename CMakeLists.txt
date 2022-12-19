# CMakeList.txt : CMake project for stend-linux, include source and define
# project specific logic here.
#

# sudo mount -t drvfs d: /mnt/d 

cmake_minimum_required (VERSION 3.12)

project ("stend-linux")

set(CMAKE_CXX_COMPILER "/usr/bin/g++-10") 

file(GLOB stend-linux_SRC
     "*.h"
     "*.cpp"
     "*.c"
     "*.cc"
     "*.hpp"
)

# Add source to this project's executable. 
add_executable (stend-linux ${stend-linux_SRC}) 

target_include_directories(stend-linux PUBLIC "/usr/include/jsoncpp")
target_link_libraries(stend-linux "drogon" "trantor" "z" "uuid" "brotlidec" "brotlienc" "brotlicommon" "jsoncpp" "cares" "pq" "pthread" "ssl" "crypto" "sodium" "systemd") 

target_compile_definitions(stend-linux PUBLIC _DEBUG)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET stend-linux PROPERTY CXX_STANDARD 20)
endif()
 
target_compile_options(stend-linux PUBLIC -fcoroutines)
#SET(GCC_COVERAGE_COMPILE_FLAGS "-fcoroutines")
 
