cmake_minimum_required(VERSION 3.12)
project(PKEET-FDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -mtune=native -ggdb")

# --- OpenSSL ---
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# --- PBC & GMP ---
include_directories(/usr/local/include/pbc)
set(PBC_LIBRARY "-lpbc")
set(GMP_LIBRARY "-lgmp")

# --- Include dirs ---
include_directories(${PROJECT_SOURCE_DIR}/include)

# --- Executable ---
add_executable(frontend
    src/IBEET_FDA.cpp
    src/LGZ22.cpp
    src/LLH24.cpp
    src/main.cpp
)

target_link_libraries(frontend
    ${PBC_LIBRARY}
    ${GMP_LIBRARY}
    ${OPENSSL_LIBRARIES}
    pthread
)

# --- Output dir ---
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)