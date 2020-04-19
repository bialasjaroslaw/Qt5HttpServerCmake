cmake_minimum_required(VERSION 3.15)
project(Qt5SslServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt5Core CONFIG REQUIRED)
find_package(Qt5Network CONFIG REQUIRED)

set(SOURCES
    qsslserver.cpp
)

set(HEADER_FILES
    qsslserver.h
    qtsslserverglobal.h
)

set(HEADER_PRIV_FILES
    qsslserver_p.h
)

set(GENERATED_HEADERS
    QSslServer
    QtSslServerGlobal
)

set(SOURCE ${HEADER_FILES} ${HEADER_PRIV_FILES})

set(LIB_NAME QtSslServer)

add_library(${PROJECT_NAME} SHARED ${SOURCES})

set(TEMP_INCLUDE_DIR ${CMAKE_BINARY_DIR}/include)
file(MAKE_DIRECTORY ${TEMP_INCLUDE_DIR})
target_include_directories(${PROJECT_NAME} PUBLIC
  $<BUILD_INTERFACE:${TEMP_INCLUDE_DIR}>
)
file(WRITE ${TEMP_INCLUDE_DIR}/${LIB_NAME}/${LIB_NAME} "")
foreach(HEADER ${GENERATED_HEADERS})
    string(TOLOWER ${HEADER} HEADER_SRC)
    file(WRITE ${TEMP_INCLUDE_DIR}/${LIB_NAME}/${HEADER} "#include \"${HEADER_SRC}.h\"\n")
    file(APPEND ${TEMP_INCLUDE_DIR}/${LIB_NAME}/${LIB_NAME} "#include \"${HEADER_SRC}.h\"\n")
endforeach()

target_link_libraries(${PROJECT_NAME} PUBLIC Qt5::Core Qt5::Network)
target_include_directories(${PROJECT_NAME}
    PUBLIC ${TEMP_INCLUDE_DIR} ${TEMP_INCLUDE_DIR}/${LIB_NAME} )

set(HEADER_FILES qsslserver.h qtsslserverglobal.h)
set(HEADER_PRIV_FILES qsslserver_p.h)
file(COPY ${HEADER_FILES} DESTINATION ${TEMP_INCLUDE_DIR}/${LIB_NAME}/)
file(COPY ${HEADER_PRIV_FILES} DESTINATION ${TEMP_INCLUDE_DIR}/private/)
