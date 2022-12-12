
file(GLOB SRCS *.c statem/*.c record/*.c)

include_directories(../crypto/)


if (SHARED_OPENSSL)
add_library(ssl SHARED ${SRCS})
else()
add_library(ssl STATIC ${SRCS})
endif()

target_link_libraries(ssl crypto)

set_target_properties(ssl PROPERTIES FOLDER "third_party/openssl")

target_include_directories(ssl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include/)

target_compile_definitions(ssl PUBLIC
	-DOPENSSL_NO_ASM
	-DOPENSSL_NO_ASYNC
	-DOPENSSL_NO_ENGINE
	-DOPENSSL_NO_RC1
	-DOPENSSL_NO_RC3
	-DOPENSSL_NO_MD1
	-DOPENSSL_NO_MD2
	-DOPENSSL_NO_MD3
	-DOPENSSL_NO_MD4
	-DOPENSSL_NO_MDC2
	-DOPENSSL_NO_WHIRLPOOL
	-DOPENSSL_NO_COMP
	-DOPENSSL_NO_CHACHA
)
