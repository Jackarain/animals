cmake_minimum_required(VERSION 3.16)
project(socks)

add_library(socks INTERFACE)

if (APPLE)
	target_sources(socks
		INTERFACE
		${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_client.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_enums.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_error_code.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_io.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_server.hpp
	)
else()
	target_sources(socks
		PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_client.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_enums.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_error_code.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_io.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_server.hpp
	)
endif()

target_include_directories(socks
	INTERFACE
	${CMAKE_CURRENT_SOURCE_DIR}/include/

	${Boost_INCLUDE_DIRS} # 上层传递的boost依赖库目录.
	${UTILS_INCLUDE_DIRS} # 上层传递的utils依赖库目录.
)

set(SOCKS_INCLUDE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}/include
	PARENT_SCOPE
)
