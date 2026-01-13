#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
set -ex
# This script synchronizes the repositories and patches defined in config.sh.
CONFIG_SCRIPT_PATH="${CONFIG_SCRIPT:-$(dirname "${BASH_SOURCE[0]}")/config.sh}"
source "$CONFIG_SCRIPT_PATH"

for entry in "${REPOS[@]}"; do
    IFS='|' read -r name url <<< "$entry"
    dir="$GITHUB_WORKSPACE/../$name"
    if [ -d "$dir" ]; then
        echo "Updating $name..."
        git -C "$dir" fetch origin
        git -C "$dir" reset --hard origin/main
        git -C "$dir" clean -fdx
    else
        echo "Cloning $name..."
        git clone "$url" "$dir"
    fi
done
