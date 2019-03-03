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
include crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/depend.make

# Include the progress variables for this target.
include crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/progress.make

# Include the compile flags for this target's objects.
include crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/flags.make

crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o: crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/flags.make
crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o: ../crypto/ecdh_extra/ecdh_extra.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o"
	cd /home/hwlee/boringssl/build/crypto/ecdh_extra && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o   -c /home/hwlee/boringssl/crypto/ecdh_extra/ecdh_extra.c

crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ecdh_extra.dir/ecdh_extra.c.i"
	cd /home/hwlee/boringssl/build/crypto/ecdh_extra && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/crypto/ecdh_extra/ecdh_extra.c > CMakeFiles/ecdh_extra.dir/ecdh_extra.c.i

crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ecdh_extra.dir/ecdh_extra.c.s"
	cd /home/hwlee/boringssl/build/crypto/ecdh_extra && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/crypto/ecdh_extra/ecdh_extra.c -o CMakeFiles/ecdh_extra.dir/ecdh_extra.c.s

crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o.requires:

.PHONY : crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o.requires

crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o.provides: crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o.requires
	$(MAKE) -f crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/build.make crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o.provides.build
.PHONY : crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o.provides

crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o.provides.build: crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o


ecdh_extra: crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o
ecdh_extra: crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/build.make

.PHONY : ecdh_extra

# Rule to build all files generated by this target.
crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/build: ecdh_extra

.PHONY : crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/build

crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/requires: crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/ecdh_extra.c.o.requires

.PHONY : crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/requires

crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/clean:
	cd /home/hwlee/boringssl/build/crypto/ecdh_extra && $(CMAKE_COMMAND) -P CMakeFiles/ecdh_extra.dir/cmake_clean.cmake
.PHONY : crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/clean

crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/depend:
	cd /home/hwlee/boringssl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/crypto/ecdh_extra /home/hwlee/boringssl/build /home/hwlee/boringssl/build/crypto/ecdh_extra /home/hwlee/boringssl/build/crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : crypto/ecdh_extra/CMakeFiles/ecdh_extra.dir/depend

