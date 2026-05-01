cmake_minimum_required(VERSION 3.25.1)
project(tssh LANGUAGES CXX)

# -----------------
# Functions
# -----------------

function(echoTrimmedMessage MSG CMDL ARG)
  execute_process(
        COMMAND ${CMDL} ${ARG}
        COMMAND tr -d '\t\n\r'
	OUTPUT_VARIABLE  RES
  )
  message("${MSG}\"${RES}\"")
endfunction()

# -----------------
# End Functions
# -----------------

# Detect the host type:
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(HOST_TYPE darwin)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(HOST_TYPE linux)
else()
  message(FATAL_ERROR "Unsupported host: ${CMAKE_SYSTEM_NAME}")
endif()

# Read the project version from file:
file(READ "${CMAKE_SOURCE_DIR}/version" VERSION_TEXT)
string(STRIP ${VERSION_TEXT} VERSION_TEXT)

# Create config.h :
file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/include/config.h" "#define VERSION \"${VERSION_TEXT}\"\n")
file(APPEND "${CMAKE_CURRENT_SOURCE_DIR}/include/config.h" "#define PACKAGE \"${PROJECT_NAME}\"\n")

# Flag to enable "native" machine code generation on Linux:
option(USE_MARCH_NATIVE "Enable navive machine code generation via -DUSE_MARCH_NATIVE=ON" OFF)

# Flag to enable compilation with Fil-C:
option(USE_FIL_C_WITH_SSL "Enable Fil-C compilation via -DUSE_FIL_C_WITH_SSL=<PATH>, specifying Fil-C compiled OpenSSL path" "")

# Set C++ Standard:
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add headers directory :
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Source files:
file(GLOB_RECURSE SRC "src/*.cpp")

# Target:
add_executable(${PROJECT_NAME} ${SRC})

# Common Compiler Options:
set(COMMON_FLAGS " -g ")

# --------------------------------
# Begin Platform specific options:
# --------------------------------

# ===> Mac OS:
if(HOST_TYPE STREQUAL "darwin")

  if(USE_FIL_C_WITH_SSL)
	  message(FATAL_ERROR "Unsupported OS for Fil-C: ${HOST_TYPE}")
  endif()

  set(OPTIMIZE "-O3")
  set(LTO "-flto=full")
  set(CPU_OPT "-march=native")
  set(ADDITIONAL_FLAGS "-Weverything -D_FORTIFY_SOURCE=2 ${OPTIMIZE} ${CPU_OPT} ${LTO} -fstack-protector --param=ssp-buffer-size=4 \
	-Wformat -Werror=format-security -Wno-deprecated-declarations -Wno-documentation -Wno-c++98-compat -Wno-padded \
	-Wno-c++98-compat-pedantic -Wno-undefined-func-template")

  echoTrimmedMessage("-- OSX CMAKE_CXX_FLAGS=" "echo" "\"${COMMON_FLAGS} ${ADDITIONAL_FLAGS}\"")

# ===> Linux OS:
elseif(HOST_TYPE STREQUAL "linux")
  set(OPTIMIZE "-O3")
  set(LTO "-flto")

  if(USE_FIL_C_WITH_SSL)
          if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
	        message(FATAL_ERROR "Unsupported CPU for Fil-C: ${CMAKE_SYSTEM_PROCESSOR}")
          else()
                set(CMAKE_CXX_COMPILER filc++)
                echoTrimmedMessage("-- Using Fil-C++:" "which" "filc++")
	        message("-- With Openssl : \"${USE_FIL_C_WITH_SSL}\"")
          endif()
  endif()

  # ------------------------------------
  # Begin Native Code Feasibility Check:
  # ------------------------------------

  if(USE_MARCH_NATIVE)
      # +++> 64‑bit ARM CPUs:
      if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")

	  message("-- Detected Arm 64 bit CPU \(${CMAKE_SYSTEM_PROCESSOR}\)")
          if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            set(CPU_OPT "-mcpu=native")
          elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
            set(CPU_OPT "-mcpu=native")
          else()
            set(CPU_OPT "")
          endif()

      # +++> 64‑bit x86 CPUs:
      elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
	  message("-- Detected x86 64 bit CPU \(${CMAKE_SYSTEM_PROCESSOR}\)")
          if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            set(CPU_OPT "-march=native")
          elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
            set(CPU_OPT "-march=native")
          else()

            set(CPU_OPT "")
          endif()

      # +++> Other CPUs:
      else()
	      message("-- Detected ${CMAKE_SYSTEM_PROCESSOR} CPU: native opt not supported")
              set(CPU_OPT "")
      endif()

  else()
         set(CPU_OPT "")

  endif()

  # ---------------------------------
  # End Native Code Feasibility Check
  # ---------------------------------

  if(NOT USE_FIL_C_WITH_SSL)
        set(ADDITIONAL_FLAGS "-Wall -Wextra -D_FORTIFY_SOURCE=2 ${OPTIMIZE} ${CPU_OPT} ${LTO} -fstack-protector \
				--param=ssp-buffer-size=4 -Wformat -Werror=format-security")

  	execute_process(
        	COMMAND echo "${COMMON_FLAGS} ${ADDITIONAL_FLAGS}"
        	COMMAND tr -d '\t\r\n'
		OUTPUT_VARIABLE CLEAN_FLAG_LIST
  	)

        message("-- Linux CMAKE_CXX_FLAGS=\"${CLEAN_FLAG_LIST}\"")

  else()

        set(ADDITIONAL_FLAGS "-Wall -Wextra -D_FORTIFY_SOURCE=2 ${OPTIMIZE} -Wformat -Werror=format-security")
	message("-- Linux Fil-C CMAKE_CXX_FLAGS=\"${COMMON_FLAGS} ${ADDITIONAL_FLAGS}\", Fil-C Environment")
  endif()

# ===> Other OSs:
else()

  if(USE_FIL_C_WITH_SSL)
	  message(FATAL_ERROR "Unsupported OS for Fil-C: ${HOST_TYPE}")
  endif()

  set(OPTIMIZE "-O3")
  set(ADDITIONAL_FLAGS "${OPTIMIZE} -Wall")
  message("-- Generic CMAKE_CXX_FLAGS=\"${COMMON_FLAGS} ${ADDITIONAL_FLAGS}\"")
endif()

# -----------------------------
# End Platform specific options
# -----------------------------

# Combine all flags together:
set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} ${ADDITIONAL_FLAGS}")

# Common Linker Options:
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_options(${PROJECT_NAME} PRIVATE "-Wl,-z,relro")
  message("-- Added Linker Flag: \"-Wl,-z,relro\"")
endif()

# OpenSSL:
if(NOT USE_FIL_C_WITH_SSL)
	# Check OpenSSL availability:
	find_package(OpenSSL REQUIRED)
	include_directories(${OPENSSL_INCLUDE_DIR})

	# Link libraries:
else()
	target_link_directories(${PROJECT_NAME} PRIVATE  ${USE_FIL_C_WITH_SSL}) 
  	message("-- FilC++ LIBRARY_PATH=\"${USE_FIL_C_WITH_SSL}\"")
        set(OPENSSL_LIBRARIES "ssl" "crypto")
endif()
target_link_libraries(${PROJECT_NAME} PRIVATE ${OPENSSL_LIBRARIES})
# End OpenSSL

# Installation Routines Rules:
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
install(FILES doc/tssh.1 DESTINATION share/man/man1)

