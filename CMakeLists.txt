cmake_minimum_required(VERSION 3.10)
project(DistributedLogAnalysis CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(tinyxml2 REQUIRED)

# Server: no XML dependency, just needs threading
add_executable(server server/server.cpp)
target_link_libraries(server PRIVATE Threads::Threads)

# Client: needs both threading and tinyxml2
add_executable(client client/client.cpp)
target_link_libraries(client PRIVATE Threads::Threads tinyxml2::tinyxml2)