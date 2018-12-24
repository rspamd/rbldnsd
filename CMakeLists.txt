cmake_minimum_required(VERSION 3.0)
project(rbldnsd C)

set(CMAKE_C_STANDARD 11)
set(RBLDNSD_VERSION 1.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

option(NO_STATS "Disable statistic counters" OFF)
option(NO_TIMES "Disable printing zone (re)load time using utimes()" OFF)
option(NO_MEMINFO "Disable memory info logging (mallinfo)" OFF)
option(NO_IPv6 "If you don't want/have IPv6 support (transport only)" OFF)
option(NO_MASTER_DUMP "To disable master-format (named) dump (-d option)" OFF)
option(NO_ZLIB "To disable usage of zlib (also LIBS - for zlib, -lz is needed)" OFF)
option(ENABLE_OPTIMIZATION "Enable extra optimizations [default: ON]"          ON)

# Process required package by using FindPackage and calling for INCLUDE_DIRECTORIES and
# setting list of required libraries
# Usage:
# ProcessPackage(VAR [OPTIONAL] [ROOT path] [INCLUDE path]
#	[LIBRARY path] [INCLUDE_SUFFIXES path1 path2 ...] [LIB_SUFFIXES path1 path2 ...]
#	[MODULES module1 module2 ...])
# params:
# OPTIONAL - do not fail if a package has not been found
# ROOT - defines root directory for a package
# INCLUDE - name of the include file to check
# LIBRARY - name of the library to check
# INCLUDE_SUFFIXES - list of include suffixes (relative to ROOT)
# LIB_SUFFIXES - list of library suffixes
# MODULES - modules to search using pkg_config
MACRO(ProcessPackage PKG_NAME)

    CMAKE_PARSE_ARGUMENTS(PKG "OPTIONAL" "ROOT;INCLUDE"
            "LIBRARY;INCLUDE_SUFFIXES;LIB_SUFFIXES;MODULES" ${ARGN})

    IF(NOT PKG_LIBRARY)
        SET(PKG_LIBRARY "${PKG_NAME}")
    ENDIF()
    IF(NOT PKG_INCLUDE)
        SET(PKG_INCLUDE "${PKG_NAME}.h")
    ENDIF()

    IF(NOT PKG_ROOT AND PKG_MODULES)
        PKG_SEARCH_MODULE(${PKG_NAME} ${PKG_MODULES})
    ENDIF()

    IF(${PKG_NAME}_FOUND)
        MESSAGE(STATUS "Found package ${PKG_NAME} in pkg-config modules ${PKG_MODULES}")
        SET(WITH_${PKG_NAME} 1 CACHE INTERNAL "")
        IF(ENABLE_STATIC MATCHES "ON")
            SET(_XPREFIX "${PKG_NAME}_STATIC")
        ELSE(ENABLE_STATIC MATCHES "ON")
            SET(_XPREFIX "${PKG_NAME}")
        ENDIF(ENABLE_STATIC MATCHES "ON")
        FOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
            INCLUDE_DIRECTORIES("${_arg}")
            SET(${PKG_NAME}_INCLUDE "${_arg}" CACHE INTERNAL "")
        ENDFOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
        FOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
            LINK_DIRECTORIES("${_arg}")
            SET(${PKG_NAME}_LIBRARY_PATH "${_arg}" CACHE INTERNAL "")
        ENDFOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
        # Handle other CFLAGS and LDFLAGS
        FOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
        FOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
        LIST(APPEND CMAKE_REQUIRED_LIBRARIES "${${_XPREFIX}_LIBRARIES}")
        INCLUDE_DIRECTORIES(${${_XPREFIX}_INCLUDEDIR})
    ELSE()
        IF(NOT ${PKG_NAME}_GUESSED)
            # Try some more heuristic
            FIND_LIBRARY(_lib NAMES ${PKG_LIBRARY}
                    HINTS ${PKG_ROOT} ${SEARCH_PATH}
                    PATH_SUFFIXES ${PKG_LIB_SUFFIXES} lib64 lib
                    PATHS ${DEFAULT_LIBRARY_PATHS})
            IF(NOT _lib)
                IF(PKG_OPTIONAL)
                    MESSAGE(STATUS "Cannot find library ${PKG_LIBRARY} for package ${PKG_NAME}, ignoring")
                ELSE()
                    MESSAGE(FATAL_ERROR "Cannot find library ${PKG_LIBRARY} for package ${PKG_NAME}")
                ENDIF()
            ENDIF(NOT _lib)

            FIND_PATH(_incl ${PKG_INCLUDE}
                    HINTS ${PKG_ROOT} ${SEARCH_PATH}
                    PATH_SUFFIXES ${PKG_INCLUDE_SUFFIXES} include
                    PATHS 	{DEFAULT_INCLUDE_PATHS})
            IF(NOT _incl)
                IF(PKG_OPTIONAL)
                    MESSAGE(STATUS "Cannot find header ${PKG_INCLUDE} for package ${PKG_NAME}")
                ELSE()
                    MESSAGE(FATAL_ERROR "Cannot find header ${PKG_INCLUDE} for package ${PKG_NAME}")
                ENDIF()
            ENDIF(NOT _incl)

            IF(_incl AND _lib)
                # We need to apply heuristic to find the real dir name
                STRING(REGEX REPLACE "/[^/]+$" "" _incl_path "${PKG_INCLUDE}")
                STRING(REGEX REPLACE "${_incl_path}/$" "" _stripped_incl "${_incl}")
                GET_FILENAME_COMPONENT(_lib_path "${_lib}" PATH)
                INCLUDE_DIRECTORIES("${_stripped_incl}")
                LINK_DIRECTORIES("${_lib_path}")
                LIST(APPEND CMAKE_REQUIRED_LIBRARIES ${_lib})
                SET(${PKG_NAME}_INCLUDE "${_stripped_incl}" CACHE INTERNAL "")
                SET(${PKG_NAME}_LIBRARY_PATH "${_lib_path}" CACHE INTERNAL "")
                SET(${PKG_NAME}_LIBRARY "${_lib}" CACHE INTERNAL "")
                SET(${PKG_NAME}_GUESSED 1 CACHE INTERNAL "")
                SET(WITH_${PKG_NAME} 1 CACHE INTERNAL "")
                MESSAGE(STATUS "Found package ${PKG_NAME} in '${_lib_path}' (${_lib}) and '${_stripped_incl}' (${PKG_INCLUDE}).")
            ENDIF()

        ELSE()
            MESSAGE(STATUS "Found package ${PKG_NAME} (cached)")
            INCLUDE_DIRECTORIES("${${PKG_NAME}_INCLUDE}")
            LINK_DIRECTORIES("${${PKG_NAME}_LIBRARY_PATH}")
            LIST(APPEND CMAKE_REQUIRED_LIBRARIES "${${PKG_NAME}_LIBRARY}")
        ENDIF()
    ENDIF(${PKG_NAME}_FOUND)

    UNSET(_lib CACHE)
    UNSET(_incl CACHE)
ENDMACRO(ProcessPackage name)

set(DEFAULT_INCLUDE_PATHS "/opt;/usr;/usr/local;/opt/local;/usr/pkg;/opt/csw;/sw")
set(DEFAULT_LIBRARY_PATHS "/usr/local;/usr/pkg;/usr;/Library/Frameworks;/sw;/opt/local;/opt/csw;/opt")

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_SOURCE_DIR}/cmake/")
include(TestBigEndian)
include(CheckFunctionExists)
include(CheckCCompilerFlag)
find_package(PkgConfig REQUIRED)
find_package(AWK REQUIRED)

test_big_endian(IS_BIG_ENDIAN)
check_function_exists(setitimer HAVE_SETITIMER)

# Some routines extracted from Rspamd
set(CMAKE_C_WARN_FLAGS "")
check_c_compiler_flag(-Wall SUPPORT_WALL)
check_c_compiler_flag(-W SUPPORT_W)
check_c_compiler_flag(-Wpointer-arith SUPPORT_WPOINTER)
check_c_compiler_flag(-Wno-unused-parameter SUPPORT_WPARAM)
check_c_compiler_flag(-Wno-unused-function SUPPORT_WFUNCTION)
check_c_compiler_flag(-Wunused-variable SUPPORT_WUNUSED_VAR)
check_c_compiler_flag(-Wno-pointer-sign SUPPORT_WPOINTER_SIGN)
check_c_compiler_flag(-Wno-sign-compare SUPPORT_WSIGN_COMPARE)
check_c_compiler_flag(-Wstrict-prototypes SUPPORT_WSTRICT_PROTOTYPES)
check_c_compiler_flag(-pedantic SUPPORT_PEDANTIC_FLAG)
check_c_compiler_flag(-Wno-unused-const-variable SUPPORT_WNO_UNUSED_CONST)
# GCC 6 specific
check_c_compiler_flag(-Wnull-dereference SUPPORT_WNULL_DEREFERENCE)
check_c_compiler_flag(-Wduplicated-cond SUPPORT_WDUPLICATED_COND)
# GCC 7 specific
check_c_compiler_flag(-Wimplicit-fallthrough SUPPORT_WIMPLICIT_FALLTHROUGH)
if(NOT "${CMAKE_C_COMPILER_ID}" MATCHES SunPro)
    check_c_compiler_flag("-std=c11" SUPPORT_STD11_FLAG)
    check_c_compiler_flag("-std=c99" SUPPORT_STD99_FLAG)
endif(NOT "${CMAKE_C_COMPILER_ID}" MATCHES SunPro)
if(SUPPORT_W)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -W")
endif(SUPPORT_W)
if(SUPPORT_WALL)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wall")
endif(SUPPORT_WALL)
if(SUPPORT_WPOINTER)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wpointer-arith")
endif(SUPPORT_WPOINTER)
if(SUPPORT_WPARAM)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-unused-parameter")
endif(SUPPORT_WPARAM)
if(SUPPORT_WFUNCTION)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-unused-function")
endif(SUPPORT_WFUNCTION)
if(SUPPORT_WUNUSED_VAR)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wunused-variable")
endif(SUPPORT_WUNUSED_VAR)
if(SUPPORT_WPOINTER_SIGN)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-pointer-sign")
endif(SUPPORT_WPOINTER_SIGN)
if(SUPPORT_WSTRICT_PROTOTYPES)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wstrict-prototypes")
endif(SUPPORT_WSTRICT_PROTOTYPES)
#IF(SUPPORT_PEDANTIC_FLAG)
#	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -pedantic")
#ENDIF(SUPPORT_PEDANTIC_FLAG)
if(SUPPORT_WNULL_DEREFERENCE)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wnull-dereference")
endif()
if(SUPPORT_WDUPLICATED_COND)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wduplicated-cond")
endif()
if(SUPPORT_WLOGICAL_OP)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wlogical-op")
endif()
if(SUPPORT_WNO_UNUSED_CONST)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-unused-const-variable")
endif()
if(SUPPORT_WSIGN_COMPARE)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-sign-compare")
endif()
if(SUPPORT_STD11_FLAG)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -std=c11")
ELSE(SUPPORT_STD11_FLAG)
    message("C11 compatible compiler is strongly recommended")
    if(SUPPORT_STD99_FLAG)
        set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -std=c99")
    endif(SUPPORT_STD99_FLAG)
endif(SUPPORT_STD11_FLAG)
if(SUPPORT_WIMPLICIT_FALLTHROUGH)
    set(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-implicit-fallthrough")
endif(SUPPORT_WIMPLICIT_FALLTHROUGH)

if(NOT CMAKE_C_OPT_FLAGS)
    if(ENABLE_OPTIMIZATION MATCHES "ON")
        check_c_compiler_flag(-flto SUPPORT_FLTO)
        if(SUPPORT_FLTO)
            if(NOT CMAKE_GCC_AR OR NOT CMAKE_GCC_RANLIB)
                find_program(CMAKE_GCC_AR NAMES "gcc-ar")
                find_program(CMAKE_GCC_RANLIB NAMES "gcc-ranlib")
                mark_as_advanced(CMAKE_GCC_AR CMAKE_GCC_RANLIB)
            endif()
            if(CMAKE_GCC_AR AND CMAKE_GCC_RANLIB)
                set(CMAKE_C_OPT_FLAGS "-g -O3 -fstrict-aliasing -flto")
                set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
                set(CMAKE_C_ARCHIVE_CREATE "${CMAKE_GCC_AR} cr <TARGET> <LINK_FLAGS> <OBJECTS>")
                set(CMAKE_C_ARCHIVE_APPEND "${CMAKE_GCC_AR} r <TARGET> <LINK_FLAGS> <OBJECTS>")
                set(CMAKE_C_ARCHIVE_FINISH "${CMAKE_GCC_RANLIB} <TARGET>")
                set(CMAKE_CXX_ARCHIVE_CREATE "${CMAKE_GCC_AR} cr <TARGET> <LINK_FLAGS> <OBJECTS>")
                set(CMAKE_CXX_ARCHIVE_APPEND "${CMAKE_GCC_AR} r <TARGET> <LINK_FLAGS> <OBJECTS>")
                set(CMAKE_CXX_ARCHIVE_FINISH "${CMAKE_GCC_RANLIB} <TARGET>")
            endif()
        else()
            set(CMAKE_C_OPT_FLAGS "-g -O3 -fstrict-aliasing")
        endif()
    else(ENABLE_OPTIMIZATION MATCHES "ON")
        if(ENABLE_FULL_DEBUG MATCHES "ON")
            set(CMAKE_C_OPT_FLAGS "-g -O0 -fstrict-aliasing")
        else(ENABLE_FULL_DEBUG MATCHES "ON")
            set(CMAKE_C_OPT_FLAGS "-g -O2 -fstrict-aliasing")
        endif(ENABLE_FULL_DEBUG MATCHES "ON")
    endif(ENABLE_OPTIMIZATION MATCHES "ON")
endif(NOT CMAKE_C_OPT_FLAGS)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND CMAKE_REQUIRED_LIBRARIES rt)
    list(APPEND CMAKE_REQUIRED_LIBRARIES dl)
    list(APPEND CMAKE_REQUIRED_LIBRARIES resolv)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_OPT_FLAGS} ${CMAKE_C_FLAGS} ${CMAKE_C_WARN_FLAGS}")

ProcessPackage(LIBZ LIBRARY z INCLUDE zlib.h INCLUDE_SUFFIXES include/zlib
        ROOT ${LIBZ_ROOT_DIR} MODULES z)

configure_file(config.h.in config.h)
add_definitions("-DHAVE_CONFIG_H")
add_subdirectory(t1ha)

add_executable(rbldnsd
        btrie.c
        dns_dnequ.c
        dns_dnlabels.c
        dns_dnlen.c
        dns_dnreverse.c
        dns_dntol.c
        dns_dntop.c
        dns_findname.c
        dns_ptodn.c
        hooks.c
        ip4atos.c
        ip4mask.c
        ip4parse.c
        ip6addr.c
        istream.c
        mempool.c
        rbldnsd.c
        rbldnsd_acl.c
        rbldnsd_combined.c
        rbldnsd_dnhash.c
        rbldnsd_dnhash_fixed.c
        rbldnsd_dnset.c
        rbldnsd_generic.c
        rbldnsd_ip4set.c
        rbldnsd_ip4trie.c
        rbldnsd_ip4tset.c
        rbldnsd_ip6trie.c
        rbldnsd_ip6tset.c
        rbldnsd_packet.c
        rbldnsd_util.c
        rbldnsd_zones.c
        ${CMAKE_CURRENT_BINARY_DIR}/dns_nametab.c)
set_target_properties(rbldnsd PROPERTIES VERSION ${RBLDNSD_VERSION})
target_link_libraries(rbldnsd t1ha)
target_link_libraries(rbldnsd ${CMAKE_REQUIRED_LIBRARIES})

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dns_nametab.c
        COMMAND ${AWK_BIN}
        ARGS    -f ${CMAKE_SOURCE_DIR}/dns_maketab.awk ${CMAKE_SOURCE_DIR}/dns.h > ${CMAKE_CURRENT_BINARY_DIR}/dns_nametab.c
        DEPENDS ${CMAKE_SOURCE_DIR}/dns_maketab.awk ${CMAKE_SOURCE_DIR}/dns.h
        COMMENT
        "[AWK][${Name}] Preprocessing awk"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})


install(TARGETS rbldnsd RUNTIME DESTINATION sbin)