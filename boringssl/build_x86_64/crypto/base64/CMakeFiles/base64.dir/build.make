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
include crypto/base64/CMakeFiles/base64.dir/depend.make

# Include the progress variables for this target.
include crypto/base64/CMakeFiles/base64.dir/progress.make

# Include the compile flags for this target's objects.
include crypto/base64/CMakeFiles/base64.dir/flags.make

crypto/base64/CMakeFiles/base64.dir/base64.c.o: crypto/base64/CMakeFiles/base64.dir/flags.make
crypto/base64/CMakeFiles/base64.dir/base64.c.o: ../crypto/base64/base64.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build_x86_64/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object crypto/base64/CMakeFiles/base64.dir/base64.c.o"
	cd /home/hwlee/boringssl/build_x86_64/crypto/base64 && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/base64.dir/base64.c.o   -c /home/hwlee/boringssl/crypto/base64/base64.c

crypto/base64/CMakeFiles/base64.dir/base64.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/base64.dir/base64.c.i"
	cd /home/hwlee/boringssl/build_x86_64/crypto/base64 && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/crypto/base64/base64.c > CMakeFiles/base64.dir/base64.c.i

crypto/base64/CMakeFiles/base64.dir/base64.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/base64.dir/base64.c.s"
	cd /home/hwlee/boringssl/build_x86_64/crypto/base64 && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/crypto/base64/base64.c -o CMakeFiles/base64.dir/base64.c.s

crypto/base64/CMakeFiles/base64.dir/base64.c.o.requires:

.PHONY : crypto/base64/CMakeFiles/base64.dir/base64.c.o.requires

crypto/base64/CMakeFiles/base64.dir/base64.c.o.provides: crypto/base64/CMakeFiles/base64.dir/base64.c.o.requires
	$(MAKE) -f crypto/base64/CMakeFiles/base64.dir/build.make crypto/base64/CMakeFiles/base64.dir/base64.c.o.provides.build
.PHONY : crypto/base64/CMakeFiles/base64.dir/base64.c.o.provides

crypto/base64/CMakeFiles/base64.dir/base64.c.o.provides.build: crypto/base64/CMakeFiles/base64.dir/base64.c.o


base64: crypto/base64/CMakeFiles/base64.dir/base64.c.o
base64: crypto/base64/CMakeFiles/base64.dir/build.make

.PHONY : base64

# Rule to build all files generated by this target.
crypto/base64/CMakeFiles/base64.dir/build: base64

.PHONY : crypto/base64/CMakeFiles/base64.dir/build

crypto/base64/CMakeFiles/base64.dir/requires: crypto/base64/CMakeFiles/base64.dir/base64.c.o.requires

.PHONY : crypto/base64/CMakeFiles/base64.dir/requires

crypto/base64/CMakeFiles/base64.dir/clean:
	cd /home/hwlee/boringssl/build_x86_64/crypto/base64 && $(CMAKE_COMMAND) -P CMakeFiles/base64.dir/cmake_clean.cmake
.PHONY : crypto/base64/CMakeFiles/base64.dir/clean

crypto/base64/CMakeFiles/base64.dir/depend:
	cd /home/hwlee/boringssl/build_x86_64 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/crypto/base64 /home/hwlee/boringssl/build_x86_64 /home/hwlee/boringssl/build_x86_64/crypto/base64 /home/hwlee/boringssl/build_x86_64/crypto/base64/CMakeFiles/base64.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : crypto/base64/CMakeFiles/base64.dir/depend

