#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# Copyright (c) 2025 Qualcomm Innovation Center, Inc. All rights reserved.
set -ex
echo "Running build script..."
# Build/Compile audioreach-graphservices
source ${GITHUB_WORKSPACE}/install/environment-setup-armv8-2a-poky-linux

# download pkg.m4
cd ${GITHUB_WORKSPACE}/install/sysroots/x86_64-pokysdk-linux/usr/share/aclocal
wget https://raw.githubusercontent.com/pkgconf/pkgconf/master/pkg.m4
cd -

# make sure we are in the right directory
cd ${GITHUB_WORKSPACE}
# Run autoreconf to generate the configure script
autoreconf -Wcross --verbose --install --force --exclude=autopoint
autoconf --force

# Run the configure script with the specified arguments
./configure CFLAGS="-Wno-int-conversion" ${BUILD_ARGS}
# make
make DESTDIR=${GITHUB_WORKSPACE}/build install
