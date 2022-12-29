cmake_minimum_required(VERSION 3.16)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW) # cmake_policy(SET CMP0077 NEW)
if (WIN32)
	cmake_policy(SET CMP0091 NEW) # for CMAKE_MSVC_RUNTIME_LIBRARY
endif()
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
project(animals)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

################################################################################

string(TIMESTAMP VERSION_YEAR "%Y")
string(TIMESTAMP VERSION_MONTH_YEAR "%m")
string(TIMESTAMP VERSION_DAY_YEAR "%j")
string(TIMESTAMP HOUR24 "%H")
string(TIMESTAMP MINUTE "%M")

math(EXPR VERSION_MAJOR "${VERSION_YEAR} - 2018")
math(EXPR VERSION_TINY "${VERSION_DAY_YEAR} % 100")
math(EXPR VERSION_MINOR "${VERSION_MONTH_YEAR} + ${VERSION_DAY_YEAR} / 100")
math(EXPR VERSION_BUILD "${HOUR24}*60+${MINUTE}")

include(CheckCXXCompilerFlag)
include(CheckLibraryExists)
include(CheckIPOSupported)

################################################################################

# Disable in-source builds to prevent source tree corruption.
if ("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()
message(STATUS "CMAKE Version: ${CMAKE_VERSION}")

message(STATUS "Source Dir: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "Host System name: ${CMAKE_HOST_SYSTEM_NAME}")

set(default_build_type "Release")

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
        STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                 "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

message(STATUS "System name: ${CMAKE_SYSTEM_NAME}")
message(STATUS "System version: ${CMAKE_SYSTEM_VERSION}")
if (WIN32)
	message(STATUS "Platform version: ${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/cmake")

include(CheckCXXLinkerFlag)

################################################################################
option(ENABLE_INTERPROCEDURAL_OPTIMIZATION "Enable Interprocedural Optimization" OFF)
option(ENABLE_INTEGRATE_SOCKS_SERVER "Enable integrate socks server" OFF)
option(ENABLE_USE_IO_URING "Enable auto use io_uring" OFF)
option(ENABLE_BUILD_WERROR "All warnings being treated as errors" OFF)

option(ENABLE_SYSTEM_ZLIB "Build with system zlib support" OFF)
option(ENABLE_SYSTEM_OPENSSL "Build with system openssl support" OFF)

option(ENABLE_TCMALLOC_STATIC "Build with Tcmalloc support" OFF)
option(ENABLE_JEMALLOC_STATIC "Build with Jemalloc support" OFF)
option(ENABLE_MIMALLOC_STATIC "Build with Mimalloc support" OFF)

option(ENABLE_GIT_VERSION "Enable git version" ON)
option(ENABLE_SYSTEMD_LOGGING "Build with systemd journal support" OFF)
option(DISABLE_WRITE_LOGGING "Build with log file writer disabled" OFF)

option(ENABLE_BUILD_WITH_LIBCXX "Build with libc++" OFF)

option(ENABLE_MOLD "build using mold" OFF)
option(ENABLE_LLD "build using lld" OFF)

option(ENABLE_BUILD_TESTS "build animals's unit tests" OFF)
option(ENABLE_LINKE_TO_LIBATOMIC "link to libatomic.so - some platform requires it" OFF)

################################################################################

if (ENABLE_INTERPROCEDURAL_OPTIMIZATION)
	check_ipo_supported(RESULT lto_supported OUTPUT lto_error)
	if (lto_supported)
		message(STATUS "IPO / LTO enabled")
		set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
	endif()
endif()

################################################################################

find_program(MOLD_LINKER mold)
find_program(LLD_LINKER lld)

################################################################################

if (ENABLE_GIT_VERSION)
	find_package(Git)
	gitGetVersion(${CMAKE_CURRENT_SOURCE_DIR} animals)
	set(VERSION_GIT ${animals_WC_REVISION_HASH})
	string(TIMESTAMP PVERSION "%Y%m%d-${VERSION_GIT}-${CMAKE_SYSTEM_NAME}")
endif()

set(CMAKE_C_STANDARD 11)

################################################################################

if (MSVC)
	set(MSVC_DISABLED_WARNINGS_LIST
		"C4702" # unreachable code
	)
	set(MSVC_LEVEL4_WARNINGS_LIST
		"C4265" # class has virtual functions, but destructor is not virtual
	)
	string(REPLACE "C" " -wd" MSVC_DISABLED_WARNINGS_STR
		${MSVC_DISABLED_WARNINGS_LIST})
	string(REPLACE "C" " -w4" MSVC_LEVEL4_WARNINGS_STR
		${MSVC_LEVEL4_WARNINGS_LIST})

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${MSVC_DISABLED_WARNINGS_STR} ${MSVC_LEVEL4_WARNINGS_STR}")
	set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} ${MSVC_DISABLED_WARNINGS_STR} ${MSVC_LEVEL4_WARNINGS_STR}")

	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

	add_definitions(
		-D_CRT_SECURE_NO_DEPRECATE
		-D_CRT_SECURE_NO_WARNINGS
		-D_CRT_NONSTDC_NO_DEPRECATE
		-D_CRT_NONSTDC_NO_WARNINGS
		-D_SCL_SECURE_NO_DEPRECATE
		-D_SCL_SECURE_NO_WARNINGS
	)

	add_definitions(
		-DWIN32_LEAN_AND_MEAN
		-D_WIN32_WINNT=0x0601
		-DNOMINMAX
		-DUNICODE
		-D_UNICODE
		-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
	)

	add_definitions(
		-DBOOST_ALL_STATIC_LINK
		-DBOOST_THREAD_USE_LIB
		-DBOOST_FILESYSTEM_STATIC_LINK
		-DBOOST_USE_WINAPI_VERSION=0x0601
	)

	add_compile_options(/utf-8)
	add_compile_options(/bigobj)
	add_compile_options(/MP)
	add_compile_options(/Zc:__cplusplus)

	message(STATUS "Set stack size: 100000000 bytes")
	add_link_options(/STACK:100000000)
	#set(CMAKE_CXX_STACK_SIZE "100000000")
	#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj /MP /Zc:__cplusplus")

	CHECK_CXX_COMPILER_FLAG(/std:c++20 COMPILER_HAS_STD_CXX20)

	if (COMPILER_HAS_STD_CXX20)
		set(CMAKE_CXX_STANDARD 20)
		set(CMAKE_CXX_STANDARD_REQUIRED ON)
		message(STATUS "Set default cxx standard: C++20")
	elseif (MSVC_VERSION GREATER_EQUAL "1900")
		set(CMAKE_CXX_STANDARD 17)
		set(CMAKE_CXX_STANDARD_REQUIRED ON)
		message(STATUS "Set default cxx standard: C++17")
	endif()
endif()

################################################################################

CHECK_CXX_COMPILER_FLAG(-fvisibility-inlines-hidden COMPILER_HAS_VISIBILITY_INLINE_HIDDEN)
CHECK_CXX_COMPILER_FLAG(-fvisibility=hidden COMPILER_HAS_VISIBILITY_HIDDEN)
CHECK_CXX_COMPILER_FLAG(-fdiagnostics-color=always COMPILER_HAS_COLOR)
CHECK_CXX_COMPILER_FLAG(-fcoroutines COMPILER_HAS_FCOROUTINES)
CHECK_CXX_COMPILER_FLAG(-fcoroutines-ts COMPILER_HAS_FCOROUTINES_TS)
CHECK_CXX_COMPILER_FLAG(-std=c++20 COMPILER_HAS_STD_CXX20)

################################################################################

if (${COMPILER_HAS_VISIBILITY_INLINE_HIDDEN})
	add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fvisibility-inlines-hidden>)
endif()

if (${COMPILER_HAS_VISIBILITY_HIDDEN})
	add_compile_options(-fvisibility=hidden)
endif()

if (${COMPILER_HAS_COLOR})
	add_compile_options(-fdiagnostics-color=always)
endif()

if (COMPILER_HAS_FCOROUTINES)
	add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fcoroutines>)
elseif(COMPILER_HAS_FCOROUTINES_TS)
	add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fcoroutines-ts>)
endif()

if (ENABLE_SYSTEMD_LOGGING)
	add_compile_definitions(USE_SYSTEMD_LOGGING)
endif()
if (DISABLE_WRITE_LOGGING)
	add_compile_definitions(DISABLE_WRITE_LOGGING)
endif()

################################################################################

if (NOT MSVC)
	if (NOT APPLE)
		if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
			if (ENABLE_BUILD_WITH_LIBCXX)
				add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-stdlib=libc++>)
				add_link_options(-stdlib=libc++)

				CHECK_LINKER_FLAG(CXX "-rtlib=compiler-rt" IS_COMPILER_RT_SUPPORTED)

				if (IS_COMPILER_RT_SUPPORTED)
					message(STATUS "clang supports compiler-rt, use it")
					add_link_options(-rtlib=compiler-rt)
				endif()
			else()
				set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
			endif()
		elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
			set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
		endif()
	endif()
	if (ANDROID)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie")
	endif()
	if (COMPILER_HAS_STD_CXX20)
		set(CMAKE_CXX_STANDARD 20)
		add_definitions(-DUSE_STD_STRING_VIEW)
		message(STATUS "Set default cxx standard: C++20")
	else()
		message(FATAL_ERROR "need at least GCC 11 or clang 14")
	endif()

	if (ENABLE_MOLD)
		if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
			if (MOLD_LINKER)
				list(APPEND CMAKE_EXE_LINKER_FLAGS "-fuse-ld=mold")
			endif()
		endif()
	endif()

	if (ENABLE_LLD)
		if (LLD_LINKER)
			list(APPEND CMAKE_EXE_LINKER_FLAGS "-fuse-ld=lld")
		endif()
	endif()

endif(NOT MSVC)

################################################################################

if (ENABLE_SYSTEM_OPENSSL)
	find_package(OpenSSL)
else()
	set(OpenSSL_FOUND TRUE)
	add_subdirectory(third_party/openssl)
	if (NOT MSVC AND NOT APPLE)
		if (NOT (CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
			set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--exclude-libs,ALL ${CMAKE_SHARED_LINKER_FLAGS}")
			set(CMAKE_MODULE_LINKER_FLAGS "-Wl,--exclude-libs,ALL ${CMAKE_MODULE_LINKER_FLAGS}")
			set(CMAKE_EXE_LINKER_FLAGS "-Wl,--exclude-libs,ALL ${CMAKE_EXE_LINKER_FLAGS}")
		endif()
	endif()
endif()
include_directories(${OPENSSL_INCLUDE_DIR})

################################################################################

if (ENABLE_BUILD_TESTS)
	set(USE_BOOST_TEST ON)
endif()

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON)

#独立编译asio时, 必须要在使用者项目定义, 否则会将
#定义BOOST_ASIO_HEADER_ONLY, 使用者将会导致符号冲突.
add_definitions(-DBOOST_ASIO_SEPARATE_COMPILATION)
add_definitions(-DBOOST_BEAST_SEPARATE_COMPILATION)

#此BOOST_ASIO_DYN_LINK只有在编译asio为动态链接的时候
#才能启用, 它在msvc下将BOOST_ASIO_DECL分别自动作为
#dllimport、dllexport添加.
#add_definitions(-DBOOST_ASIO_DYN_LINK)

add_definitions(-DBOOST_LOCALE_HIDE_AUTO_PTR)
add_definitions(-DBOOST_BIND_GLOBAL_PLACEHOLDERS)
add_definitions(-DBOOST_DISABLE_PRAGMA_MESSAGE)
add_definitions(-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
add_definitions(-DBOOST_PROCESS_USE_STD_FS)
if (ENABLE_USE_IO_URING)
	find_package(IOUring)

	if (IOUring_FOUND)
		message(STATUS "Linux using io_uring...")
		add_definitions(-DBOOST_ASIO_HAS_IO_URING -DBOOST_ASIO_DISABLE_EPOLL)
		link_libraries(${IOUring_LIBRARIES})
	endif()
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	add_definitions(-DBOOST_ASIO_HAS_CO_AWAIT)
endif()

set(Boost_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost)
add_subdirectory(third_party/boost EXCLUDE_FROM_ALL)

################################################################################

find_package(Threads)
link_libraries(${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

################################################################################

if (ENABLE_TCMALLOC_STATIC)
	find_package(Tcmalloc)
	link_libraries(${Tcmalloc_LIBRARY})
endif()

################################################################################

if (ENABLE_JEMALLOC_STATIC)
	find_package(JeMalloc)
	link_libraries(${JEMALLOC_LIBRARIES})
endif()

################################################################################

if (ENABLE_MIMALLOC_STATIC)
	add_definitions(-DUSE_MIMALLOC)
	set(mimalloc_DIR ${CMAKE_SOURCE_DIR}/third_party/mimalloc/cmake)

	set(MI_DEBUG_FULL        OFF CACHE BOOL "" FORCE) # Use full internal heap invariant checking in DEBUG mode (expensive)
	set(MI_PADDING           ON  CACHE BOOL "" FORCE) # Enable padding to detect heap block overflow (used only in DEBUG mode)
	if (APPLE)
		set(MI_OVERRIDE        OFF CACHE BOOL "" FORCE) # Override the standard malloc interface (e.g. define entry points for malloc() etc)
	else()
		set(MI_OVERRIDE        ON  CACHE BOOL "" FORCE)
	endif()
	set(MI_XMALLOC           OFF CACHE BOOL "" FORCE) # Enable abort() call on memory allocation failure by default
	set(MI_SHOW_ERRORS       OFF CACHE BOOL "" FORCE) # Show error and warning messages by default (only enabled by default in DEBUG mode)
	set(MI_USE_CXX           ON  CACHE BOOL "" FORCE) # Use the C++ compiler to compile the library (instead of the C compiler)
	set(MI_SEE_ASM           OFF CACHE BOOL "" FORCE) # Generate assembly files
	set(MI_INTERPOSE         ON  CACHE BOOL "" FORCE) # Use interpose to override standard malloc on macOS
	set(MI_OSX_ZONE          ON  CACHE BOOL "" FORCE) # Use malloc zone to override standard malloc on macOS
	set(MI_LOCAL_DYNAMIC_TLS OFF CACHE BOOL "" FORCE) # Use slightly slower, dlopen-compatible TLS mechanism (Unix)
	set(MI_BUILD_SHARED      OFF CACHE BOOL "" FORCE) # Build shared library
	set(MI_BUILD_STATIC      ON  CACHE BOOL "" FORCE) # Build static library
	set(MI_BUILD_OBJECT      OFF CACHE BOOL "" FORCE) # Build object library
	set(MI_BUILD_TESTS       OFF CACHE BOOL "" FORCE) # Build test executables
	set(MI_DEBUG_TSAN        OFF CACHE BOOL "" FORCE) # Build with thread sanitizer (needs clang)
	set(MI_DEBUG_UBSAN       OFF CACHE BOOL "" FORCE) # Build with undefined-behavior sanitizer (needs clang++)
	set(MI_INSTALL_TOPLEVEL  OFF CACHE BOOL "" FORCE) # Install directly into $CMAKE_INSTALL_PREFIX instead of PREFIX/lib/mimalloc-version

	include_directories(third_party/mimalloc/include)
	add_subdirectory(third_party/mimalloc EXCLUDE_FROM_ALL)

	if (MI_OVERRIDE)
		add_definitions(-DMI_OVERRIDE) # For preprocessor checks in our source.
	endif()
endif()

################################################################################

if (ENABLE_SYSTEMD_LOGGING)
	link_libraries(systemd)
endif()

################################################################################

if (WIN32 OR NOT ENABLE_SYSTEM_ZLIB)
	add_subdirectory(third_party/zlib EXCLUDE_FROM_ALL)

	set(ZLIB_LIBRARIES zlibstatic)
	set(ZLIB_INCLUDE_DIRS
		${CMAKE_CURRENT_SOURCE_DIR}/third_party/zlib
		${CMAKE_CURRENT_SOURCE_DIR}/third_party/zlib/contrib/minizip
	)
else()
	find_package(ZLIB REQUIRED)
endif()

################################################################################

add_subdirectory(third_party/fmt)

################################################################################

add_subdirectory(utils)
add_subdirectory(proxy)
add_subdirectory(animals)


################################################################################

include_directories(third_party
	${ZLIB_INCLUDE_DIRS}
	${UTILS_INCLUDE_DIRS}
	${PROXY_INCLUDE_DIRS}
	${ANIMALS_INCLUDE_DIRS}
)

################################################################################


link_libraries(
		Boost::thread
		Boost::date_time
		Boost::program_options
		Boost::json

		fmt

		${OPENSSL_LIBRARIES}
		${ZLIB_LIBRARIES}
		${UTILS_LIBRARIES}
		${ANIMALS_LIBRARIES}
)

if (WIN32)
		if (MINGW)
			link_libraries(
				secur32
				ws2_32
				mswsock
				bcrypt
				iphlpapi
			)
		else()
			link_libraries(
				Secur32.lib
				Bcrypt.lib
				Winmm.lib
				Mswsock.lib
			)
		endif()
elseif (UNIX AND NOT APPLE)
	# aviod link std::filesystem fail.
	set(std_fs_workaround "")
	if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
		set(std_fs_workaround stdc++fs)
	endif()

	link_libraries(
		${std_fs_workaround}
	)
endif()

if (ENABLE_LINKE_TO_LIBATOMIC)
	link_libraries(atomic)
endif()

################################################################################

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if (WIN32)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/debug)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/release)
endif()

################################################################################

add_subdirectory(examples)

################################################################################

if (ENABLE_BUILD_TESTS)
	link_libraries(Boost::test)

	enable_testing()
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/animals/include)
	add_subdirectory(unittests)
endif()

################################################################################

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/animals.service DESTINATION /usr/lib/systemd/system/)
