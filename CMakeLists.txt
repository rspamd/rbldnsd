CMAKE_MINIMUM_REQUIRED(VERSION 3.9 FATAL_ERROR)
project(rbldnsd C ASM)

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
option(ENABLE_JEMALLOC     "Build rbldnsd with jemalloc allocator  [default: OFF]" OFF)

set(DEFAULT_INCLUDE_PATHS "/opt;/usr;/usr/local;/opt/local;/usr/pkg;/opt/csw;/sw")
set(DEFAULT_LIBRARY_PATHS "/usr/local;/usr/pkg;/usr;/Library/Frameworks;/sw;/opt/local;/opt/csw;/opt")

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")
include(TestBigEndian)
test_big_endian(IS_BIG_ENDIAN)
include(Toolset)
include(Sanitizer)
include(CheckFunctionExists)
include(CheckCCompilerFlag)
include(AsmOp)
include(FindArch)
include(ArchDep)
include(ProcessPackage)
find_package(PkgConfig REQUIRED)
find_package(AWK REQUIRED)


check_function_exists(setitimer HAVE_SETITIMER)

IF(ENABLE_JEMALLOC MATCHES "ON")
    ProcessPackage(JEMALLOC LIBRARY jemalloc_pic jemalloc INCLUDE jemalloc.h INCLUDE_SUFFIXES include/jemalloc
            ROOT ${JEMALLOC_ROOT_DIR} MODULES jemalloc)
    SET(WITH_JEMALLOC "1")
    LIST(APPEND CMAKE_REQUIRED_LIBRARIES "-lpthread")
ENDIF()


ProcessPackage(LIBZ LIBRARY z INCLUDE zlib.h INCLUDE_SUFFIXES include/zlib
        ROOT ${LIBZ_ROOT_DIR} MODULES z)
ProcessPackage(LIBEV LIBRARY ev INCLUDE ev.h INCLUDE_SUFFIXES include/ev include/libev
        ROOT ${LIBEV_ROOT_DIR} MODULES libev)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND CMAKE_REQUIRED_LIBRARIES rt)
    list(APPEND CMAKE_REQUIRED_LIBRARIES dl)
    list(APPEND CMAKE_REQUIRED_LIBRARIES resolv)
    add_definitions("-D_GNU_SOURCE")
    set(WITH_RECVMMSG "1")
endif()

configure_file(config.h.in config.h)
add_definitions("-DHAVE_CONFIG_H")
add_subdirectory(t1ha)
add_subdirectory(sds)

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
        rbldnsd_aclkey.c
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
target_link_libraries(rbldnsd sds)
target_link_libraries(rbldnsd ${RSPAMD_REQUIRED_LIBRARIES} ${CMAKE_REQUIRED_LIBRARIES})

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dns_nametab.c
        COMMAND ${AWK_BIN}
        ARGS    -f ${CMAKE_SOURCE_DIR}/dns_maketab.awk ${CMAKE_SOURCE_DIR}/dns.h > ${CMAKE_CURRENT_BINARY_DIR}/dns_nametab.c
        DEPENDS ${CMAKE_SOURCE_DIR}/dns_maketab.awk ${CMAKE_SOURCE_DIR}/dns.h
        COMMENT
        "[AWK][${Name}] Preprocessing awk"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})


install(TARGETS rbldnsd RUNTIME DESTINATION sbin)