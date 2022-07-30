# libdl-hunk - dynamic linking library
This is a dynamic linking library that uses the symbol hunks in unstripped Amiga Hunk executables without the need to create hand-crafted symbol export tables.
It implements the dlfcn.h interface with the `dlopen`, `dlerror`, `dlclose` and `dlsym` functions. The `RTLD_LAZY`, `RTLD_NOW` and `RTLD_LOCAL` flags are defined for source code compatibility, `RTLD_GLOBAL` is not supported.

## Building
The library can be built with GCC and vbcc using their respective makefiles. Other compilers could also work as it's written in C89 without any external dependencies.

## Usage
To use it simply link both the program and dynamic libraries with `libdl.a` or `dl.lib`. Make sure the exported symbols are not stripped from the dynamic library executables.

## License
The library is available under the MIT license.

## Acknowledgments
The Hunk parsing function is loosely based on HunkFunc by Dirk Stoecker, which is in turn based on HunkFunk by Olaf Barthel.
