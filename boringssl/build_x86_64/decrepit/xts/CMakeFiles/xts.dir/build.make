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
include decrepit/xts/CMakeFiles/xts.dir/depend.make

# Include the progress variables for this target.
include decrepit/xts/CMakeFiles/xts.dir/progress.make

# Include the compile flags for this target's objects.
include decrepit/xts/CMakeFiles/xts.dir/flags.make

decrepit/xts/CMakeFiles/xts.dir/xts.c.o: decrepit/xts/CMakeFiles/xts.dir/flags.make
decrepit/xts/CMakeFiles/xts.dir/xts.c.o: ../decrepit/xts/xts.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build_x86_64/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object decrepit/xts/CMakeFiles/xts.dir/xts.c.o"
	cd /home/hwlee/boringssl/build_x86_64/decrepit/xts && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/xts.dir/xts.c.o   -c /home/hwlee/boringssl/decrepit/xts/xts.c

decrepit/xts/CMakeFiles/xts.dir/xts.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/xts.dir/xts.c.i"
	cd /home/hwlee/boringssl/build_x86_64/decrepit/xts && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/decrepit/xts/xts.c > CMakeFiles/xts.dir/xts.c.i

decrepit/xts/CMakeFiles/xts.dir/xts.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/xts.dir/xts.c.s"
	cd /home/hwlee/boringssl/build_x86_64/decrepit/xts && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/decrepit/xts/xts.c -o CMakeFiles/xts.dir/xts.c.s

decrepit/xts/CMakeFiles/xts.dir/xts.c.o.requires:

.PHONY : decrepit/xts/CMakeFiles/xts.dir/xts.c.o.requires

decrepit/xts/CMakeFiles/xts.dir/xts.c.o.provides: decrepit/xts/CMakeFiles/xts.dir/xts.c.o.requires
	$(MAKE) -f decrepit/xts/CMakeFiles/xts.dir/build.make decrepit/xts/CMakeFiles/xts.dir/xts.c.o.provides.build
.PHONY : decrepit/xts/CMakeFiles/xts.dir/xts.c.o.provides

decrepit/xts/CMakeFiles/xts.dir/xts.c.o.provides.build: decrepit/xts/CMakeFiles/xts.dir/xts.c.o


xts: decrepit/xts/CMakeFiles/xts.dir/xts.c.o
xts: decrepit/xts/CMakeFiles/xts.dir/build.make

.PHONY : xts

# Rule to build all files generated by this target.
decrepit/xts/CMakeFiles/xts.dir/build: xts

.PHONY : decrepit/xts/CMakeFiles/xts.dir/build

decrepit/xts/CMakeFiles/xts.dir/requires: decrepit/xts/CMakeFiles/xts.dir/xts.c.o.requires

.PHONY : decrepit/xts/CMakeFiles/xts.dir/requires

decrepit/xts/CMakeFiles/xts.dir/clean:
	cd /home/hwlee/boringssl/build_x86_64/decrepit/xts && $(CMAKE_COMMAND) -P CMakeFiles/xts.dir/cmake_clean.cmake
.PHONY : decrepit/xts/CMakeFiles/xts.dir/clean

decrepit/xts/CMakeFiles/xts.dir/depend:
	cd /home/hwlee/boringssl/build_x86_64 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/decrepit/xts /home/hwlee/boringssl/build_x86_64 /home/hwlee/boringssl/build_x86_64/decrepit/xts /home/hwlee/boringssl/build_x86_64/decrepit/xts/CMakeFiles/xts.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : decrepit/xts/CMakeFiles/xts.dir/depend

