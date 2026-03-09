#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
set -ex
echo "Running build script..."
# Build/Compile audioreach-graphservices
source ${GITHUB_WORKSPACE}/install/environment-setup-cortexa7t2hf-neon-vfpv4-poky-linux-gnueabi
# make sure we are in the right directory
cd ${GITHUB_WORKSPACE}

# Run autoreconf to generate the configure script
autoreconf -Wcross --verbose --install --force --exclude=autopoint
autoconf --force
# Run the configure script with the specified arguments
./configure CFLAGS="-Wno-incompatible-pointer-types" ${BUILD_ARGS}
# make
make DESTDIR=${GITHUB_WORKSPACE}/build install
