# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/hwlee/boringssl

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/hwlee/boringssl/build

# Include any dependencies generated for this target.
include crypto/hkdf/CMakeFiles/hkdf.dir/depend.make

# Include the progress variables for this target.
include crypto/hkdf/CMakeFiles/hkdf.dir/progress.make

# Include the compile flags for this target's objects.
include crypto/hkdf/CMakeFiles/hkdf.dir/flags.make

crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o: crypto/hkdf/CMakeFiles/hkdf.dir/flags.make
crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o: ../crypto/hkdf/hkdf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o"
	cd /home/hwlee/boringssl/build/crypto/hkdf && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hkdf.dir/hkdf.c.o   -c /home/hwlee/boringssl/crypto/hkdf/hkdf.c

crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hkdf.dir/hkdf.c.i"
	cd /home/hwlee/boringssl/build/crypto/hkdf && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/crypto/hkdf/hkdf.c > CMakeFiles/hkdf.dir/hkdf.c.i

crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hkdf.dir/hkdf.c.s"
	cd /home/hwlee/boringssl/build/crypto/hkdf && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/crypto/hkdf/hkdf.c -o CMakeFiles/hkdf.dir/hkdf.c.s

crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o.requires:

.PHONY : crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o.requires

crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o.provides: crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o.requires
	$(MAKE) -f crypto/hkdf/CMakeFiles/hkdf.dir/build.make crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o.provides.build
.PHONY : crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o.provides

crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o.provides.build: crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o


hkdf: crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o
hkdf: crypto/hkdf/CMakeFiles/hkdf.dir/build.make

.PHONY : hkdf

# Rule to build all files generated by this target.
crypto/hkdf/CMakeFiles/hkdf.dir/build: hkdf

.PHONY : crypto/hkdf/CMakeFiles/hkdf.dir/build

crypto/hkdf/CMakeFiles/hkdf.dir/requires: crypto/hkdf/CMakeFiles/hkdf.dir/hkdf.c.o.requires

.PHONY : crypto/hkdf/CMakeFiles/hkdf.dir/requires

crypto/hkdf/CMakeFiles/hkdf.dir/clean:
	cd /home/hwlee/boringssl/build/crypto/hkdf && $(CMAKE_COMMAND) -P CMakeFiles/hkdf.dir/cmake_clean.cmake
.PHONY : crypto/hkdf/CMakeFiles/hkdf.dir/clean

crypto/hkdf/CMakeFiles/hkdf.dir/depend:
	cd /home/hwlee/boringssl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/crypto/hkdf /home/hwlee/boringssl/build /home/hwlee/boringssl/build/crypto/hkdf /home/hwlee/boringssl/build/crypto/hkdf/CMakeFiles/hkdf.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : crypto/hkdf/CMakeFiles/hkdf.dir/depend
