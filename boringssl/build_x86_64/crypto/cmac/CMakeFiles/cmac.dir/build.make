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
CMAKE_BINARY_DIR = /home/hwlee/boringssl/build_x86_64

# Include any dependencies generated for this target.
include crypto/cmac/CMakeFiles/cmac.dir/depend.make

# Include the progress variables for this target.
include crypto/cmac/CMakeFiles/cmac.dir/progress.make

# Include the compile flags for this target's objects.
include crypto/cmac/CMakeFiles/cmac.dir/flags.make

crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o: crypto/cmac/CMakeFiles/cmac.dir/flags.make
crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o: ../crypto/cmac/cmac.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build_x86_64/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o"
	cd /home/hwlee/boringssl/build_x86_64/crypto/cmac && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/cmac.dir/cmac.c.o   -c /home/hwlee/boringssl/crypto/cmac/cmac.c

crypto/cmac/CMakeFiles/cmac.dir/cmac.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/cmac.dir/cmac.c.i"
	cd /home/hwlee/boringssl/build_x86_64/crypto/cmac && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/crypto/cmac/cmac.c > CMakeFiles/cmac.dir/cmac.c.i

crypto/cmac/CMakeFiles/cmac.dir/cmac.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/cmac.dir/cmac.c.s"
	cd /home/hwlee/boringssl/build_x86_64/crypto/cmac && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/crypto/cmac/cmac.c -o CMakeFiles/cmac.dir/cmac.c.s

crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o.requires:

.PHONY : crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o.requires

crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o.provides: crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o.requires
	$(MAKE) -f crypto/cmac/CMakeFiles/cmac.dir/build.make crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o.provides.build
.PHONY : crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o.provides

crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o.provides.build: crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o


cmac: crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o
cmac: crypto/cmac/CMakeFiles/cmac.dir/build.make

.PHONY : cmac

# Rule to build all files generated by this target.
crypto/cmac/CMakeFiles/cmac.dir/build: cmac

.PHONY : crypto/cmac/CMakeFiles/cmac.dir/build

crypto/cmac/CMakeFiles/cmac.dir/requires: crypto/cmac/CMakeFiles/cmac.dir/cmac.c.o.requires

.PHONY : crypto/cmac/CMakeFiles/cmac.dir/requires

crypto/cmac/CMakeFiles/cmac.dir/clean:
	cd /home/hwlee/boringssl/build_x86_64/crypto/cmac && $(CMAKE_COMMAND) -P CMakeFiles/cmac.dir/cmake_clean.cmake
.PHONY : crypto/cmac/CMakeFiles/cmac.dir/clean

crypto/cmac/CMakeFiles/cmac.dir/depend:
	cd /home/hwlee/boringssl/build_x86_64 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/crypto/cmac /home/hwlee/boringssl/build_x86_64 /home/hwlee/boringssl/build_x86_64/crypto/cmac /home/hwlee/boringssl/build_x86_64/crypto/cmac/CMakeFiles/cmac.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : crypto/cmac/CMakeFiles/cmac.dir/depend

