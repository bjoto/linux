#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

#Includes
. prereqs.sh

XSKDIR=xdpprogs
XSKOBJ=xdpxceiver
SPECFILE=veth.spec

if [ ! -f ${SPECFILE} ]; then
    test_exit 5
fi

VETH0=$(cat ${SPECFILE} | cut -d':' -f 1)
VETH1=$(cat ${SPECFILE} | cut -d':' -f 2 | cut -d',' -f 1)
NS1=$(cat ${SPECFILE} | cut -d':' -f 2 | cut -d',' -f 2)

vethXDPnative ${VETH0} ${VETH1} ${NS1}

./${XSKDIR}/${XSKOBJ} -i ${VETH0} -i ${VETH1},${NS1} -N -T -C 10000

retval=$?

cleanup_exit ${VETH0} ${VETH1} ${NS1}

test_exit $retval
