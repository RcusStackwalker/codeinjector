cmake_minimum_required(VERSION 3.12)
project(codeinjector)

set(SRC_LIST
	main.c
	supported_ecus.c
	supported_ecus.h)

add_executable(${PROJECT_NAME} ${SRC_LIST})

if(APPLE)
    include(ExternalProject)

    execute_process(
        COMMAND brew --prefix
        OUTPUT_VARIABLE HOMEBREW_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    execute_process(
        COMMAND brew --prefix binutils
        OUTPUT_VARIABLE BINUTILS_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(NOT BINUTILS_PREFIX OR NOT EXISTS "${BINUTILS_PREFIX}")
        message(FATAL_ERROR "Homebrew binutils not found. Run: brew install binutils")
    endif()

    # Homebrew omits libiberty.a from the bottle — build it from source
    ExternalProject_Add(libiberty_project
        URL "https://ftpmirror.gnu.org/gnu/binutils/binutils-2.46.0.tar.bz2"
        URL_HASH SHA256=0f3152632a2a9ce066f20963e9bb40af7cf85b9b6c409ed892fd0676e84ecd12
        INSTALL_DIR "${CMAKE_BINARY_DIR}/libiberty_install"
        CONFIGURE_COMMAND <SOURCE_DIR>/libiberty/configure
            --prefix=<INSTALL_DIR>
            --enable-install-libiberty
        BUILD_COMMAND $(MAKE)
        INSTALL_COMMAND $(MAKE) install
        BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libiberty.a"
    )

    ExternalProject_Get_Property(libiberty_project install_dir)
    add_library(libiberty STATIC IMPORTED GLOBAL)
    add_dependencies(libiberty libiberty_project)
    set_property(TARGET libiberty PROPERTY IMPORTED_LOCATION "${install_dir}/lib/libiberty.a")

    find_library(LIB_BFD    NAMES bfd    PATHS "${BINUTILS_PREFIX}/lib" NO_DEFAULT_PATH REQUIRED)
    find_library(LIB_SFRAME NAMES sframe PATHS "${BINUTILS_PREFIX}/lib" NO_DEFAULT_PATH REQUIRED)
    find_library(LIB_ZSTD   NAMES zstd   PATHS "${HOMEBREW_PREFIX}/lib" REQUIRED)
    find_library(LIB_Z      NAMES z      REQUIRED)

    target_include_directories(${PROJECT_NAME} PRIVATE "${BINUTILS_PREFIX}/include")

    # bfd.h requires PACKAGE/PACKAGE_VERSION before inclusion (GNU autoconf convention)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        PACKAGE="codeinjector"
        PACKAGE_VERSION="1.0"
    )

    target_link_libraries(${PROJECT_NAME}
        "${LIB_BFD}"
        "${LIB_SFRAME}"
        libiberty
        "${LIB_ZSTD}"
        "${LIB_Z}"
    )
else()
    target_link_libraries(${PROJECT_NAME} bfd dl)
endif()

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
install(FILES ${PROJECT_NAME}-config.cmake DESTINATION lib/${PROJECT_NAME})
