cmake_minimum_required(VERSION 3.15)
project(Qt5HttpServer)

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
find_package(Qt5WebSockets CONFIG REQUIRED)


set(SOURCES
    ../3rdparty/http-parser/http_parser.c
    ../3rdparty/http-parser/http_parser.h
    qabstracthttpserver.cpp
    qhttpserver.cpp
    qhttpserverliterals.cpp
    qhttpserverrequest.cpp
    qhttpserverresponder.cpp
    qhttpserverresponse.cpp
    qhttpserverrouter.cpp
    qhttpserverrouterrule.cpp
    )

set(HEADER_FILES
    qabstracthttpserver.h
    qhttpserver.h
    qhttpserverrequest.h
    qhttpserverresponder.h
    qhttpserverresponse.h
    qhttpserverrouter.h
    qhttpserverrouterrule.h
    qhttpserverrouterviewtraits.h
    qthttpserverglobal.h
    )

set(GENERATED_HEADERS
    QAbstractHttpServer
    QHttpServer
    QHttpServerRequest
    QHttpServerResponder
    QHttpServerResponse
    QHttpServerRouter
    QHttpServerRouterRule
    QHttpServerRouterViewTraits
    )

set(HEADER_PRIV_FILES
    qabstracthttpserver_p.h
    qhttpserver_p.h
    qhttpserverliterals_p.h
    qhttpserverrequest_p.h
    qhttpserverresponder_p.h
    qhttpserverresponse_p.h
    qhttpserverrouter_p.h
    qhttpserverrouterrule_p.h
    )

set(SOURCE ${HEADER_FILES} ${HEADER_PRIV_FILES})

set(LIB_NAME QtHttpServer)

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

target_link_libraries(${PROJECT_NAME} PUBLIC Qt5::Core Qt5::Network Qt5::WebSockets Qt5::CorePrivate Qt5SslServer)
target_include_directories(${PROJECT_NAME}
    PUBLIC ${TEMP_INCLUDE_DIR} ${TEMP_INCLUDE_DIR}/${LIB_NAME}
    PRIVATE ../3rdparty/http-parser)
target_compile_definitions(${PROJECT_NAME}
    PUBLIC QT_USE_QSTRINGBUILDER QT_DEPRECATED_WARNINGS QT_FEATURE_SSL=1)

file(COPY ${HEADER_FILES} DESTINATION ${TEMP_INCLUDE_DIR}/${LIB_NAME}/)
file(COPY ${HEADER_PRIV_FILES} DESTINATION ${TEMP_INCLUDE_DIR}/private/)
