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
include crypto/pool/CMakeFiles/pool.dir/depend.make

# Include the progress variables for this target.
include crypto/pool/CMakeFiles/pool.dir/progress.make

# Include the compile flags for this target's objects.
include crypto/pool/CMakeFiles/pool.dir/flags.make

crypto/pool/CMakeFiles/pool.dir/pool.c.o: crypto/pool/CMakeFiles/pool.dir/flags.make
crypto/pool/CMakeFiles/pool.dir/pool.c.o: ../crypto/pool/pool.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build_x86_64/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object crypto/pool/CMakeFiles/pool.dir/pool.c.o"
	cd /home/hwlee/boringssl/build_x86_64/crypto/pool && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pool.dir/pool.c.o   -c /home/hwlee/boringssl/crypto/pool/pool.c

crypto/pool/CMakeFiles/pool.dir/pool.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pool.dir/pool.c.i"
	cd /home/hwlee/boringssl/build_x86_64/crypto/pool && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/crypto/pool/pool.c > CMakeFiles/pool.dir/pool.c.i

crypto/pool/CMakeFiles/pool.dir/pool.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pool.dir/pool.c.s"
	cd /home/hwlee/boringssl/build_x86_64/crypto/pool && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/crypto/pool/pool.c -o CMakeFiles/pool.dir/pool.c.s

crypto/pool/CMakeFiles/pool.dir/pool.c.o.requires:

.PHONY : crypto/pool/CMakeFiles/pool.dir/pool.c.o.requires

crypto/pool/CMakeFiles/pool.dir/pool.c.o.provides: crypto/pool/CMakeFiles/pool.dir/pool.c.o.requires
	$(MAKE) -f crypto/pool/CMakeFiles/pool.dir/build.make crypto/pool/CMakeFiles/pool.dir/pool.c.o.provides.build
.PHONY : crypto/pool/CMakeFiles/pool.dir/pool.c.o.provides

crypto/pool/CMakeFiles/pool.dir/pool.c.o.provides.build: crypto/pool/CMakeFiles/pool.dir/pool.c.o


pool: crypto/pool/CMakeFiles/pool.dir/pool.c.o
pool: crypto/pool/CMakeFiles/pool.dir/build.make

.PHONY : pool

# Rule to build all files generated by this target.
crypto/pool/CMakeFiles/pool.dir/build: pool

.PHONY : crypto/pool/CMakeFiles/pool.dir/build

crypto/pool/CMakeFiles/pool.dir/requires: crypto/pool/CMakeFiles/pool.dir/pool.c.o.requires

.PHONY : crypto/pool/CMakeFiles/pool.dir/requires

crypto/pool/CMakeFiles/pool.dir/clean:
	cd /home/hwlee/boringssl/build_x86_64/crypto/pool && $(CMAKE_COMMAND) -P CMakeFiles/pool.dir/cmake_clean.cmake
.PHONY : crypto/pool/CMakeFiles/pool.dir/clean

crypto/pool/CMakeFiles/pool.dir/depend:
	cd /home/hwlee/boringssl/build_x86_64 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/crypto/pool /home/hwlee/boringssl/build_x86_64 /home/hwlee/boringssl/build_x86_64/crypto/pool /home/hwlee/boringssl/build_x86_64/crypto/pool/CMakeFiles/pool.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : crypto/pool/CMakeFiles/pool.dir/depend

