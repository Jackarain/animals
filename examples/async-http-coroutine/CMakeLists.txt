set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DENABLE_LOGGER")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")

file(GLOB async_http_coroutine_SRCS
	async-http-coroutine.cpp
)

add_executable(async_http_coroutine
	${async_http_coroutine_SRCS}
)

if (ENABLE_MIMALLOC_STATIC)
	target_link_libraries(async_http_coroutine mimalloc-static)
endif()

target_link_libraries(async_http_coroutine
	Boost::asio
	Boost::beast

	animals
)

if (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129 AND CMAKE_VERSION VERSION_GREATER 3.20.3)
	set_property(TARGET async_http_coroutine PROPERTY CXX_STANDARD 23)
	message(STATUS "async_http_coroutine set cxx standard: C++23")
else()
	set_property(TARGET async_http_coroutine PROPERTY CXX_STANDARD 20)
	message(STATUS "async_http_coroutine set cxx standard: C++20")
endif()

target_include_directories(async_http_coroutine PUBLIC
	${CMAKE_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	target_compile_options(async_http_coroutine PRIVATE -fcoroutines)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	target_compile_definitions(async_http_coroutine PRIVATE -DBOOST_ASIO_HAS_CO_AWAIT)
endif()

if(ENABLE_BUILD_WERROR)
	if(MSVC)
		target_compile_options(async_http_coroutine PRIVATE /W4 /WX)
	elseif(UNIX AND NOT APPLE)
		if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
			target_compile_options(async_http_coroutine PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
		else()
			target_compile_options(async_http_coroutine PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated -Wno-deprecated-copy -Wno-error=deprecated-copy -Wno-pessimizing-move)
		endif()
	endif()
endif()

set_target_properties(async_http_coroutine PROPERTIES FOLDER "examples")
