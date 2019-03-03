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
include crypto/dsa/CMakeFiles/dsa.dir/depend.make

# Include the progress variables for this target.
include crypto/dsa/CMakeFiles/dsa.dir/progress.make

# Include the compile flags for this target's objects.
include crypto/dsa/CMakeFiles/dsa.dir/flags.make

crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o: crypto/dsa/CMakeFiles/dsa.dir/flags.make
crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o: ../crypto/dsa/dsa.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build_x86_64/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o"
	cd /home/hwlee/boringssl/build_x86_64/crypto/dsa && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/dsa.dir/dsa.c.o   -c /home/hwlee/boringssl/crypto/dsa/dsa.c

crypto/dsa/CMakeFiles/dsa.dir/dsa.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dsa.dir/dsa.c.i"
	cd /home/hwlee/boringssl/build_x86_64/crypto/dsa && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/crypto/dsa/dsa.c > CMakeFiles/dsa.dir/dsa.c.i

crypto/dsa/CMakeFiles/dsa.dir/dsa.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dsa.dir/dsa.c.s"
	cd /home/hwlee/boringssl/build_x86_64/crypto/dsa && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/crypto/dsa/dsa.c -o CMakeFiles/dsa.dir/dsa.c.s

crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o.requires:

.PHONY : crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o.requires

crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o.provides: crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o.requires
	$(MAKE) -f crypto/dsa/CMakeFiles/dsa.dir/build.make crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o.provides.build
.PHONY : crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o.provides

crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o.provides.build: crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o


crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o: crypto/dsa/CMakeFiles/dsa.dir/flags.make
crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o: ../crypto/dsa/dsa_asn1.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build_x86_64/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o"
	cd /home/hwlee/boringssl/build_x86_64/crypto/dsa && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/dsa.dir/dsa_asn1.c.o   -c /home/hwlee/boringssl/crypto/dsa/dsa_asn1.c

crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dsa.dir/dsa_asn1.c.i"
	cd /home/hwlee/boringssl/build_x86_64/crypto/dsa && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hwlee/boringssl/crypto/dsa/dsa_asn1.c > CMakeFiles/dsa.dir/dsa_asn1.c.i

crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dsa.dir/dsa_asn1.c.s"
	cd /home/hwlee/boringssl/build_x86_64/crypto/dsa && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hwlee/boringssl/crypto/dsa/dsa_asn1.c -o CMakeFiles/dsa.dir/dsa_asn1.c.s

crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o.requires:

.PHONY : crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o.requires

crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o.provides: crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o.requires
	$(MAKE) -f crypto/dsa/CMakeFiles/dsa.dir/build.make crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o.provides.build
.PHONY : crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o.provides

crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o.provides.build: crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o


dsa: crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o
dsa: crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o
dsa: crypto/dsa/CMakeFiles/dsa.dir/build.make

.PHONY : dsa

# Rule to build all files generated by this target.
crypto/dsa/CMakeFiles/dsa.dir/build: dsa

.PHONY : crypto/dsa/CMakeFiles/dsa.dir/build

crypto/dsa/CMakeFiles/dsa.dir/requires: crypto/dsa/CMakeFiles/dsa.dir/dsa.c.o.requires
crypto/dsa/CMakeFiles/dsa.dir/requires: crypto/dsa/CMakeFiles/dsa.dir/dsa_asn1.c.o.requires

.PHONY : crypto/dsa/CMakeFiles/dsa.dir/requires

crypto/dsa/CMakeFiles/dsa.dir/clean:
	cd /home/hwlee/boringssl/build_x86_64/crypto/dsa && $(CMAKE_COMMAND) -P CMakeFiles/dsa.dir/cmake_clean.cmake
.PHONY : crypto/dsa/CMakeFiles/dsa.dir/clean

crypto/dsa/CMakeFiles/dsa.dir/depend:
	cd /home/hwlee/boringssl/build_x86_64 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/crypto/dsa /home/hwlee/boringssl/build_x86_64 /home/hwlee/boringssl/build_x86_64/crypto/dsa /home/hwlee/boringssl/build_x86_64/crypto/dsa/CMakeFiles/dsa.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : crypto/dsa/CMakeFiles/dsa.dir/depend

