SET(SDSSRC     sds.c)

add_library(sds STATIC ${SDSSRC})

IF(ENABLE_FULL_DEBUG MATCHES "OFF")
    if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
        SET_TARGET_PROPERTIES(sds PROPERTIES COMPILE_FLAGS "-O3")
    endif ()
ENDIF()
