#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
set -e
# This script synchronizes the repositories and patches defined in config.sh.
CONFIG_SCRIPT_PATH="${CONFIG_SCRIPT:-$(dirname "${BASH_SOURCE[0]}")/config.sh}"
source "$CONFIG_SCRIPT_PATH"

for entry in "${PATCHES[@]}"; do
    IFS='|' read -r name patch <<< "$entry"
    dir="$GITHUB_WORKSPACE/../$name"
    echo "Applying patch from $name..."
    git -C "$GITHUB_WORKSPACE" apply --check "$dir/$patch" && git -C "$GITHUB_WORKSPACE" apply "$dir/$patch" || echo "Patch already applied or failed."
    echo "Done applying patch from $name."
done
