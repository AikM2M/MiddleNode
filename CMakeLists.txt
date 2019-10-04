# Note: on OS X you should install XCode and the associated command-line tools

## compilation/linkage settings
enable_language(CXX)
INCLUDE_DIRECTORIES(
    .
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_BINARY_DIR}
    )

IF (WIN32)
  	ADD_DEFINITIONS(/DCMAKE_BUILD /D_CRT_SECURE_NO_DEPRECATE)
ENDIF()

add_subdirectory(Lib)

ADD_EXECUTABLE(MiddleNode MiddleNode.cpp)

TARGET_LINK_LIBRARIES(MiddleNode Resource PEP ACP paho-mqtt3cs sqlite3 ssl crypto)




                
