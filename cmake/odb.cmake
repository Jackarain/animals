function(ADD_ODB_INTERFACE ODB_HEADERS)

if (NOT ARGN)
	message(SEND_ERROR "no header file")
endif()

get_filename_component(ODB_HEADER_BASE ${ARGV1} NAME_WE)

set(ODB_HEADER ${ARGV1})
set(OUT_DIR ${ARGV2})

add_custom_command(OUTPUT
		${OUT_DIR}/${ODB_HEADER_BASE}.sql
		COMMAND ${ODB_COMPILER} ARGS
		-d pgsql --std c++11 -p boost --generate-schema --generate-query --generate-schema-only --pgsql-server-version 9.6
		${ARGV3} ${ARGV4} ${ARGV5} ${ARGV6} ${ARGV7} ${ARGV8}
		${ODB_HEADER}
		-I ${ODB_INCLUDE_DIRS}
		-I ${ODB_LIB_DIR}
		-I ${ODB_PGSQL_LIB_DIR}
		-I ${ODB_BOOST_LIB_DIR}
		-I ${Boost_INCLUDE_DIRS}
		MAIN_DEPENDENCY ${ODB_HEADER}
		DEPENDS ${ODB_HEADER}
		WORKING_DIRECTORY ${OUT_DIR}
		COMMENT "generating SQL definations for ${ODB_HEADER_BASE}"
		VERBATIM)

add_custom_command(OUTPUT
		${OUT_DIR}/${ODB_HEADER_BASE}-odb.cxx
		${OUT_DIR}/${ODB_HEADER_BASE}-odb.hxx
		${OUT_DIR}/${ODB_HEADER_BASE}-odb.ihh
		COMMAND ${ODB_COMPILER} ARGS
		--ixx-suffix .ihh
		-d pgsql --std c++11 -p boost --generate-query --generate-schema --schema-format embedded --pgsql-server-version 9.6
		${ARGV3} ${ARGV4} ${ARGV5} ${ARGV6} ${ARGV7} ${ARGV8}
		${ODB_HEADER}
		-I ${ODB_INCLUDE_DIRS}
		-I ${ODB_LIB_DIR}
		-I ${ODB_PGSQL_LIB_DIR}
		-I ${ODB_BOOST_LIB_DIR}
		-I ${Boost_INCLUDE_DIRS}
		MAIN_DEPENDENCY ${ODB_HEADER}
		DEPENDS ${ODB_HEADER}
		WORKING_DIRECTORY ${OUT_DIR}
		COMMENT "generating ODB bindings for ${ODB_HEADER_BASE}"
		VERBATIM)

set(${ODB_HEADERS})

set(${ODB_HEADERS}
	${OUT_DIR}/${ODB_HEADER_BASE}-odb.cxx
	${OUT_DIR}/${ODB_HEADER_BASE}-odb.hxx
	${OUT_DIR}/${ODB_HEADER_BASE}-odb.ihh PARENT_SCOPE)

endfunction(ADD_ODB_INTERFACE)
