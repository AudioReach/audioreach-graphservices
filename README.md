# AudioReach Graph Service

## Introduction

This repository hosts a set of platform independent graph service libraries and implementation of abstraction layer for different OS and platform.  These libraries together setup and manage audio graphs in the signal processing framework.

## Documentation

Refer AudioReach docs [here](https://audioreach.github.io/design/args_design.html)

## Build instructions

Graph service repository supports various build systems: Android, Autotools. CMake is work in progress.
#### OpenEmbedded

Refer meta-audioreach [README](https://github.com/Audioreach/meta-audioreach?tab=readme-ov-file#openembedded-build--development-process) for instructions to use Graph Service on OpenEmbedded system.

#### Manual Compilation

Please note that this instruction is written for Autotools.

##### Environment Setup & Software Dependency
```bash
sudo apt-get install autoconf automake libtool
sudo apt-get install glib-2.0
```

##### Configure & Make
```bash
cd <path_to_audioreach-graphservices>
autoreconf --install
# Run command ./configure --help to check configuration options.
./configure <config options>
make
make install
```

**NOTE**: `make install` command uses /usr/local/ as the default installation directory. Use DESTDIR argument to specify different path.

##### Example

```bash
./configure --with-syslog --with-glib --without-cutils --with-dummy_diag --with-are_on_apps
make
make DESTDIR=<Absolute path to installation dir> install
```

## License

Graph service is licensed under the BSD-3-Clause. Check out the [LICENSE](LICENSE) for more details.
