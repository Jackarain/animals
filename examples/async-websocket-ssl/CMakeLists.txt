file(GLOB async_websocket_ssl_SRCS
	async-websocket-ssl.cpp
)

add_executable(async_websocket_ssl
	${async_websocket_ssl_SRCS}
)

if (ENABLE_MIMALLOC_STATIC)
	target_link_libraries(async_websocket_ssl mimalloc-static)
endif()

target_link_libraries(async_websocket_ssl
	Boost::asio
	Boost::beast

	animals
)

if (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129 AND CMAKE_VERSION VERSION_GREATER 3.20.3)
	set_property(TARGET async_websocket_ssl PROPERTY CXX_STANDARD 23)
	message(STATUS "async_websocket_ssl set cxx standard: C++23")
else()
	set_property(TARGET async_websocket_ssl PROPERTY CXX_STANDARD 20)
	message(STATUS "async_websocket_ssl set cxx standard: C++20")
endif()

target_include_directories(async_websocket_ssl PUBLIC
	${CMAKE_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	target_compile_options(async_websocket_ssl PRIVATE -fcoroutines)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	target_compile_definitions(async_websocket_ssl PRIVATE -DBOOST_ASIO_HAS_CO_AWAIT)
endif()

if(ENABLE_BUILD_WERROR)
	if(MSVC)
		target_compile_options(async_websocket_ssl PRIVATE /W4 /WX)
	elseif(UNIX AND NOT APPLE)
		if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
			target_compile_options(async_websocket_ssl PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
		else()
			target_compile_options(async_websocket_ssl PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated -Wno-deprecated-copy -Wno-error=deprecated-copy -Wno-pessimizing-move)
		endif()
	endif()
endif()

set_target_properties(async_websocket_ssl PROPERTIES FOLDER "examples")
