find_program(CODEINJECTOR_EXECUTABLE NAMES codeinjector)

if (NOT ${CODEINJECTOR_EXECUTABLE} AND CODEINJECTOR_FIND_REQUIRED)
	message(FATAL_ERROR "codeinjector required but not found")
endif()

function(invoke_codeinjector ecu_name original_file injection_file output_file output_xml_file)
	add_custom_command(OUTPUT ${output_file} ${output_xml_file}
		COMMAND ${CODEINJECTOR_EXECUTABLE} ARGS ${ecu_name} ${original_file} ${injection_file} ${output_file} > ${output_xml_file}
		DEPENDS ${original_file} ${injection_file})
endfunction(invoke_codeinjector)
