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
include crypto/test/CMakeFiles/test_support.dir/depend.make

# Include the progress variables for this target.
include crypto/test/CMakeFiles/test_support.dir/progress.make

# Include the compile flags for this target's objects.
include crypto/test/CMakeFiles/test_support.dir/flags.make

crypto/test/CMakeFiles/test_support.dir/file_test.cc.o: crypto/test/CMakeFiles/test_support.dir/flags.make
crypto/test/CMakeFiles/test_support.dir/file_test.cc.o: ../crypto/test/file_test.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object crypto/test/CMakeFiles/test_support.dir/file_test.cc.o"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_support.dir/file_test.cc.o -c /home/hwlee/boringssl/crypto/test/file_test.cc

crypto/test/CMakeFiles/test_support.dir/file_test.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_support.dir/file_test.cc.i"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hwlee/boringssl/crypto/test/file_test.cc > CMakeFiles/test_support.dir/file_test.cc.i

crypto/test/CMakeFiles/test_support.dir/file_test.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_support.dir/file_test.cc.s"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hwlee/boringssl/crypto/test/file_test.cc -o CMakeFiles/test_support.dir/file_test.cc.s

crypto/test/CMakeFiles/test_support.dir/file_test.cc.o.requires:

.PHONY : crypto/test/CMakeFiles/test_support.dir/file_test.cc.o.requires

crypto/test/CMakeFiles/test_support.dir/file_test.cc.o.provides: crypto/test/CMakeFiles/test_support.dir/file_test.cc.o.requires
	$(MAKE) -f crypto/test/CMakeFiles/test_support.dir/build.make crypto/test/CMakeFiles/test_support.dir/file_test.cc.o.provides.build
.PHONY : crypto/test/CMakeFiles/test_support.dir/file_test.cc.o.provides

crypto/test/CMakeFiles/test_support.dir/file_test.cc.o.provides.build: crypto/test/CMakeFiles/test_support.dir/file_test.cc.o


crypto/test/CMakeFiles/test_support.dir/malloc.cc.o: crypto/test/CMakeFiles/test_support.dir/flags.make
crypto/test/CMakeFiles/test_support.dir/malloc.cc.o: ../crypto/test/malloc.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object crypto/test/CMakeFiles/test_support.dir/malloc.cc.o"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_support.dir/malloc.cc.o -c /home/hwlee/boringssl/crypto/test/malloc.cc

crypto/test/CMakeFiles/test_support.dir/malloc.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_support.dir/malloc.cc.i"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hwlee/boringssl/crypto/test/malloc.cc > CMakeFiles/test_support.dir/malloc.cc.i

crypto/test/CMakeFiles/test_support.dir/malloc.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_support.dir/malloc.cc.s"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hwlee/boringssl/crypto/test/malloc.cc -o CMakeFiles/test_support.dir/malloc.cc.s

crypto/test/CMakeFiles/test_support.dir/malloc.cc.o.requires:

.PHONY : crypto/test/CMakeFiles/test_support.dir/malloc.cc.o.requires

crypto/test/CMakeFiles/test_support.dir/malloc.cc.o.provides: crypto/test/CMakeFiles/test_support.dir/malloc.cc.o.requires
	$(MAKE) -f crypto/test/CMakeFiles/test_support.dir/build.make crypto/test/CMakeFiles/test_support.dir/malloc.cc.o.provides.build
.PHONY : crypto/test/CMakeFiles/test_support.dir/malloc.cc.o.provides

crypto/test/CMakeFiles/test_support.dir/malloc.cc.o.provides.build: crypto/test/CMakeFiles/test_support.dir/malloc.cc.o


crypto/test/CMakeFiles/test_support.dir/test_util.cc.o: crypto/test/CMakeFiles/test_support.dir/flags.make
crypto/test/CMakeFiles/test_support.dir/test_util.cc.o: ../crypto/test/test_util.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object crypto/test/CMakeFiles/test_support.dir/test_util.cc.o"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_support.dir/test_util.cc.o -c /home/hwlee/boringssl/crypto/test/test_util.cc

crypto/test/CMakeFiles/test_support.dir/test_util.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_support.dir/test_util.cc.i"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hwlee/boringssl/crypto/test/test_util.cc > CMakeFiles/test_support.dir/test_util.cc.i

crypto/test/CMakeFiles/test_support.dir/test_util.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_support.dir/test_util.cc.s"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hwlee/boringssl/crypto/test/test_util.cc -o CMakeFiles/test_support.dir/test_util.cc.s

crypto/test/CMakeFiles/test_support.dir/test_util.cc.o.requires:

.PHONY : crypto/test/CMakeFiles/test_support.dir/test_util.cc.o.requires

crypto/test/CMakeFiles/test_support.dir/test_util.cc.o.provides: crypto/test/CMakeFiles/test_support.dir/test_util.cc.o.requires
	$(MAKE) -f crypto/test/CMakeFiles/test_support.dir/build.make crypto/test/CMakeFiles/test_support.dir/test_util.cc.o.provides.build
.PHONY : crypto/test/CMakeFiles/test_support.dir/test_util.cc.o.provides

crypto/test/CMakeFiles/test_support.dir/test_util.cc.o.provides.build: crypto/test/CMakeFiles/test_support.dir/test_util.cc.o


crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o: crypto/test/CMakeFiles/test_support.dir/flags.make
crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o: ../crypto/test/wycheproof_util.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hwlee/boringssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_support.dir/wycheproof_util.cc.o -c /home/hwlee/boringssl/crypto/test/wycheproof_util.cc

crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_support.dir/wycheproof_util.cc.i"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hwlee/boringssl/crypto/test/wycheproof_util.cc > CMakeFiles/test_support.dir/wycheproof_util.cc.i

crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_support.dir/wycheproof_util.cc.s"
	cd /home/hwlee/boringssl/build/crypto/test && /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hwlee/boringssl/crypto/test/wycheproof_util.cc -o CMakeFiles/test_support.dir/wycheproof_util.cc.s

crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o.requires:

.PHONY : crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o.requires

crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o.provides: crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o.requires
	$(MAKE) -f crypto/test/CMakeFiles/test_support.dir/build.make crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o.provides.build
.PHONY : crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o.provides

crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o.provides.build: crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o


test_support: crypto/test/CMakeFiles/test_support.dir/file_test.cc.o
test_support: crypto/test/CMakeFiles/test_support.dir/malloc.cc.o
test_support: crypto/test/CMakeFiles/test_support.dir/test_util.cc.o
test_support: crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o
test_support: crypto/test/CMakeFiles/test_support.dir/build.make

.PHONY : test_support

# Rule to build all files generated by this target.
crypto/test/CMakeFiles/test_support.dir/build: test_support

.PHONY : crypto/test/CMakeFiles/test_support.dir/build

crypto/test/CMakeFiles/test_support.dir/requires: crypto/test/CMakeFiles/test_support.dir/file_test.cc.o.requires
crypto/test/CMakeFiles/test_support.dir/requires: crypto/test/CMakeFiles/test_support.dir/malloc.cc.o.requires
crypto/test/CMakeFiles/test_support.dir/requires: crypto/test/CMakeFiles/test_support.dir/test_util.cc.o.requires
crypto/test/CMakeFiles/test_support.dir/requires: crypto/test/CMakeFiles/test_support.dir/wycheproof_util.cc.o.requires

.PHONY : crypto/test/CMakeFiles/test_support.dir/requires

crypto/test/CMakeFiles/test_support.dir/clean:
	cd /home/hwlee/boringssl/build/crypto/test && $(CMAKE_COMMAND) -P CMakeFiles/test_support.dir/cmake_clean.cmake
.PHONY : crypto/test/CMakeFiles/test_support.dir/clean

crypto/test/CMakeFiles/test_support.dir/depend:
	cd /home/hwlee/boringssl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hwlee/boringssl /home/hwlee/boringssl/crypto/test /home/hwlee/boringssl/build /home/hwlee/boringssl/build/crypto/test /home/hwlee/boringssl/build/crypto/test/CMakeFiles/test_support.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : crypto/test/CMakeFiles/test_support.dir/depend
