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
include decrepit/cast/CMakeFiles/cast.dir/depend.make

# Include the progress variables for this target.
include decrepit/cast/CMakeFiles/cast.dir/progress.make

# Include the compile flags for this target's objects.
include decrepit/cast/CMakeFiles/cast.dir/flags.make

decrepit/cast/CMakeFiles/cast.dir/cast.c.o: decrepit/cast/CMakeFiles/cast.dir/flags.make
decrepit/cast/CMakeFiles/cast.dir/cast.c.o: ../decrepit/cast/cast.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object decrepit/cast/CMakeFiles/cast.dir/cast.c.o"
	cd /home/hwlee/boringssl/build/decrepit/cast && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/cast.dir/cast.c.o   -c /home/hwlee/boringssl/decrepit/cast/cast.c

decrepit/cast/CMakeFiles/cast.dir/cast.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/cast.dir/cast.c.i"
	cd /home/hwlee/boringssl/build/decrepit/cast && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/decrepit/cast/cast.c > CMakeFiles/cast.dir/cast.c.i

decrepit/cast/CMakeFiles/cast.dir/cast.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/cast.dir/cast.c.s"
	cd /home/hwlee/boringssl/build/decrepit/cast && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/decrepit/cast/cast.c -o CMakeFiles/cast.dir/cast.c.s

decrepit/cast/CMakeFiles/cast.dir/cast.c.o.requires:

.PHONY : decrepit/cast/CMakeFiles/cast.dir/cast.c.o.requires

decrepit/cast/CMakeFiles/cast.dir/cast.c.o.provides: decrepit/cast/CMakeFiles/cast.dir/cast.c.o.requires
	$(MAKE) -f decrepit/cast/CMakeFiles/cast.dir/build.make decrepit/cast/CMakeFiles/cast.dir/cast.c.o.provides.build
.PHONY : decrepit/cast/CMakeFiles/cast.dir/cast.c.o.provides

decrepit/cast/CMakeFiles/cast.dir/cast.c.o.provides.build: decrepit/cast/CMakeFiles/cast.dir/cast.c.o


decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o: decrepit/cast/CMakeFiles/cast.dir/flags.make
decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o: ../decrepit/cast/cast_tables.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o"
	cd /home/hwlee/boringssl/build/decrepit/cast && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/cast.dir/cast_tables.c.o   -c /home/hwlee/boringssl/decrepit/cast/cast_tables.c

decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/cast.dir/cast_tables.c.i"
	cd /home/hwlee/boringssl/build/decrepit/cast && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/decrepit/cast/cast_tables.c > CMakeFiles/cast.dir/cast_tables.c.i

decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/cast.dir/cast_tables.c.s"
	cd /home/hwlee/boringssl/build/decrepit/cast && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/decrepit/cast/cast_tables.c -o CMakeFiles/cast.dir/cast_tables.c.s

decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o.requires:

.PHONY : decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o.requires

decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o.provides: decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o.requires
	$(MAKE) -f decrepit/cast/CMakeFiles/cast.dir/build.make decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o.provides.build
.PHONY : decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o.provides

decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o.provides.build: decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o


cast: decrepit/cast/CMakeFiles/cast.dir/cast.c.o
cast: decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o
cast: decrepit/cast/CMakeFiles/cast.dir/build.make

.PHONY : cast

# Rule to build all files generated by this target.
decrepit/cast/CMakeFiles/cast.dir/build: cast

.PHONY : decrepit/cast/CMakeFiles/cast.dir/build

decrepit/cast/CMakeFiles/cast.dir/requires: decrepit/cast/CMakeFiles/cast.dir/cast.c.o.requires
decrepit/cast/CMakeFiles/cast.dir/requires: decrepit/cast/CMakeFiles/cast.dir/cast_tables.c.o.requires

.PHONY : decrepit/cast/CMakeFiles/cast.dir/requires

decrepit/cast/CMakeFiles/cast.dir/clean:
	cd /home/hwlee/boringssl/build/decrepit/cast && $(CMAKE_COMMAND) -P CMakeFiles/cast.dir/cmake_clean.cmake
.PHONY : decrepit/cast/CMakeFiles/cast.dir/clean

decrepit/cast/CMakeFiles/cast.dir/depend:
	cd /home/hwlee/boringssl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/decrepit/cast /home/hwlee/boringssl/build /home/hwlee/boringssl/build/decrepit/cast /home/hwlee/boringssl/build/decrepit/cast/CMakeFiles/cast.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : decrepit/cast/CMakeFiles/cast.dir/depend

