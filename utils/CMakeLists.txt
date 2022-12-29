cmake_minimum_required(VERSION 3.16)
project(utils)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DENABLE_LOGGER")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")

add_library(utils STATIC)

target_sources(utils
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/include/utils/async_connect.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/utils/internal.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/utils/logging.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/utils/misc.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/utils/scoped_exit.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/utils/asio_util.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/utils/default_cert.hpp

	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/src/misc.cpp
)

target_include_directories(utils
	PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include/
)

target_link_libraries(utils
	Boost::asio
	Boost::beast
	fmt
)

set(UTILS_INCLUDE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}/include
	PARENT_SCOPE
)

set(UTILS_LIBRARIES
	utils
	PARENT_SCOPE
)
