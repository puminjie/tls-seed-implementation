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
CMAKE_BINARY_DIR = /home/hwlee/boringssl/build64

# Include any dependencies generated for this target.
include decrepit/evp/CMakeFiles/evp_decrepit.dir/depend.make

# Include the progress variables for this target.
include decrepit/evp/CMakeFiles/evp_decrepit.dir/progress.make

# Include the compile flags for this target's objects.
include decrepit/evp/CMakeFiles/evp_decrepit.dir/flags.make

decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o: decrepit/evp/CMakeFiles/evp_decrepit.dir/flags.make
decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o: ../decrepit/evp/dss1.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build64/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o"
	cd /home/hwlee/boringssl/build64/decrepit/evp && /home/hwlee/devel/rpi/toolchains/aarch64/bin/aarch64-linux-gnu-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/evp_decrepit.dir/dss1.c.o   -c /home/hwlee/boringssl/decrepit/evp/dss1.c

decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/evp_decrepit.dir/dss1.c.i"
	$(CMAKE_COMMAND) -E cmake_unimplemented_variable CMAKE_C_CREATE_PREPROCESSED_SOURCE

decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/evp_decrepit.dir/dss1.c.s"
	$(CMAKE_COMMAND) -E cmake_unimplemented_variable CMAKE_C_CREATE_ASSEMBLY_SOURCE

decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o.requires:

.PHONY : decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o.requires

decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o.provides: decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o.requires
	$(MAKE) -f decrepit/evp/CMakeFiles/evp_decrepit.dir/build.make decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o.provides.build
.PHONY : decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o.provides

decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o.provides.build: decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o


decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o: decrepit/evp/CMakeFiles/evp_decrepit.dir/flags.make
decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o: ../decrepit/evp/evp_do_all.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build64/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o"
	cd /home/hwlee/boringssl/build64/decrepit/evp && /home/hwlee/devel/rpi/toolchains/aarch64/bin/aarch64-linux-gnu-gcc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/evp_decrepit.dir/evp_do_all.c.o   -c /home/hwlee/boringssl/decrepit/evp/evp_do_all.c

decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/evp_decrepit.dir/evp_do_all.c.i"
	$(CMAKE_COMMAND) -E cmake_unimplemented_variable CMAKE_C_CREATE_PREPROCESSED_SOURCE

decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/evp_decrepit.dir/evp_do_all.c.s"
	$(CMAKE_COMMAND) -E cmake_unimplemented_variable CMAKE_C_CREATE_ASSEMBLY_SOURCE

decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o.requires:

.PHONY : decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o.requires

decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o.provides: decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o.requires
	$(MAKE) -f decrepit/evp/CMakeFiles/evp_decrepit.dir/build.make decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o.provides.build
.PHONY : decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o.provides

decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o.provides.build: decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o


evp_decrepit: decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o
evp_decrepit: decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o
evp_decrepit: decrepit/evp/CMakeFiles/evp_decrepit.dir/build.make

.PHONY : evp_decrepit

# Rule to build all files generated by this target.
decrepit/evp/CMakeFiles/evp_decrepit.dir/build: evp_decrepit

.PHONY : decrepit/evp/CMakeFiles/evp_decrepit.dir/build

decrepit/evp/CMakeFiles/evp_decrepit.dir/requires: decrepit/evp/CMakeFiles/evp_decrepit.dir/dss1.c.o.requires
decrepit/evp/CMakeFiles/evp_decrepit.dir/requires: decrepit/evp/CMakeFiles/evp_decrepit.dir/evp_do_all.c.o.requires

.PHONY : decrepit/evp/CMakeFiles/evp_decrepit.dir/requires

decrepit/evp/CMakeFiles/evp_decrepit.dir/clean:
	cd /home/hwlee/boringssl/build64/decrepit/evp && $(CMAKE_COMMAND) -P CMakeFiles/evp_decrepit.dir/cmake_clean.cmake
.PHONY : decrepit/evp/CMakeFiles/evp_decrepit.dir/clean

decrepit/evp/CMakeFiles/evp_decrepit.dir/depend:
	cd /home/hwlee/boringssl/build64 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/decrepit/evp /home/hwlee/boringssl/build64 /home/hwlee/boringssl/build64/decrepit/evp /home/hwlee/boringssl/build64/decrepit/evp/CMakeFiles/evp_decrepit.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : decrepit/evp/CMakeFiles/evp_decrepit.dir/depend

