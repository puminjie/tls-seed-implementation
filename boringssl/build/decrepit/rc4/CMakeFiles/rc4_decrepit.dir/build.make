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
include decrepit/rc4/CMakeFiles/rc4_decrepit.dir/depend.make

# Include the progress variables for this target.
include decrepit/rc4/CMakeFiles/rc4_decrepit.dir/progress.make

# Include the compile flags for this target's objects.
include decrepit/rc4/CMakeFiles/rc4_decrepit.dir/flags.make

decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o: decrepit/rc4/CMakeFiles/rc4_decrepit.dir/flags.make
decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o: ../decrepit/rc4/rc4_decrepit.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o"
	cd /home/hwlee/boringssl/build/decrepit/rc4 && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o   -c /home/hwlee/boringssl/decrepit/rc4/rc4_decrepit.c

decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.i"
	cd /home/hwlee/boringssl/build/decrepit/rc4 && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/decrepit/rc4/rc4_decrepit.c > CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.i

decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.s"
	cd /home/hwlee/boringssl/build/decrepit/rc4 && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/decrepit/rc4/rc4_decrepit.c -o CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.s

decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o.requires:

.PHONY : decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o.requires

decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o.provides: decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o.requires
	$(MAKE) -f decrepit/rc4/CMakeFiles/rc4_decrepit.dir/build.make decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o.provides.build
.PHONY : decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o.provides

decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o.provides.build: decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o


rc4_decrepit: decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o
rc4_decrepit: decrepit/rc4/CMakeFiles/rc4_decrepit.dir/build.make

.PHONY : rc4_decrepit

# Rule to build all files generated by this target.
decrepit/rc4/CMakeFiles/rc4_decrepit.dir/build: rc4_decrepit

.PHONY : decrepit/rc4/CMakeFiles/rc4_decrepit.dir/build

decrepit/rc4/CMakeFiles/rc4_decrepit.dir/requires: decrepit/rc4/CMakeFiles/rc4_decrepit.dir/rc4_decrepit.c.o.requires

.PHONY : decrepit/rc4/CMakeFiles/rc4_decrepit.dir/requires

decrepit/rc4/CMakeFiles/rc4_decrepit.dir/clean:
	cd /home/hwlee/boringssl/build/decrepit/rc4 && $(CMAKE_COMMAND) -P CMakeFiles/rc4_decrepit.dir/cmake_clean.cmake
.PHONY : decrepit/rc4/CMakeFiles/rc4_decrepit.dir/clean

decrepit/rc4/CMakeFiles/rc4_decrepit.dir/depend:
	cd /home/hwlee/boringssl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/decrepit/rc4 /home/hwlee/boringssl/build /home/hwlee/boringssl/build/decrepit/rc4 /home/hwlee/boringssl/build/decrepit/rc4/CMakeFiles/rc4_decrepit.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : decrepit/rc4/CMakeFiles/rc4_decrepit.dir/depend

