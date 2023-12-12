#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

build_dir=/build/kbuild
install_dir=/build/kernels
log_dir=/build/kernels/logs

mkdir -p "${log_dir}" || true

exec 3< <($d/generate_build_configs.sh)
while read -u 3 xlen config fragment toolchain; do
    n="${xlen}_${toolchain}_${config//_/-}_$(basename $fragment)"

    echo "::group::Building linux_${n}"
    rc=0
    $d/build_kernel.sh "${xlen}" "${config}" "${fragment}" "${toolchain}" \
                       "${build_dir}" "${install_dir}" \
                       > >(tee -a ${log_dir}/build_kernel_${n}.log) \
                       2> >(tee -a ${log_dir}/build_kernel_error_${n}.log >&1) || rc=$?
    echo "::endgroup::"
    if (( $rc )); then
        echo "::error::FAIL linux_${n}"
    else
        echo "::notice::OK linux_${n}"
    fi
done

