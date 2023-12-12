#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

kernels_dir=/build/kernels
rootfs_dir=/rootfs

xlen=$1
config=$2
fragment=$3
toolchain=$4
rootfs=$5

lnx="${kernels_dir}/${xlen}_${toolchain}_${config//_/-}_$(basename $fragment)"
rootfs=$(echo ${rootfs_dir}/rootfs_${xlen}_${rootfs}_*.tar.xz)

echo "::group::Testing ${lnx} ${rootfs}"
rc=0
$d/run_test.sh "${lnx}" "${rootfs}" || rc=$?
echo "::endgroup::"
if (( $rc )); then
    echo "::error::FAIL ${lnx} ${rootfs}"
else
    echo "::notice::OK ${lnx} ${rootfs}"
fi
