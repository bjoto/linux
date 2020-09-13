#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

#Includes
. prereqs.sh

URANDOM=/dev/urandom
[ ! -e "${URANDOM}" ] && { echo "${URANDOM} not found. Skipping tests."; test_exit 1; }

VETH0_POSTFIX=$(cat ${URANDOM} | tr -dc '0-9' | fold -w 256 | head -n 1 | head --bytes 4)
VETH0=ve${VETH0_POSTFIX}
NS0=af_xdp${VETH0_POSTFIX}
VETH1_POSTFIX=$(cat ${URANDOM} | tr -dc '0-9' | fold -w 256 | head -n 1 | head --bytes 4)
VETH1=ve${VETH1_POSTFIX}
NS1=af_xdp${VETH1_POSTFIX}
IPADDR_VETH0=192.168.222.1/30
IPADDR_VETH1=192.168.222.2/30
MTU=1500
SPECFILE=veth.spec

setup_vethPairs() {
    echo "setting up ${VETH0}: root: ${IPADDR_VETH0}"
    ip netns add ${NS1}
    ip link add ${VETH0} type veth peer name ${VETH1}
	ip addr add dev ${VETH0} ${IPADDR_VETH0}
    echo "setting up ${VETH1}: ${NS1}: ${IPADDR_VETH1}"
	ip link set ${VETH1} netns ${NS1}
	ip netns exec ${NS1} ip addr add dev ${VETH1} ${IPADDR_VETH1}
	ip netns exec ${NS1} ip link set ${VETH1} mtu ${MTU}
	ip netns exec ${NS1} ip link set ${VETH1} up
    ip link set ${VETH0} mtu ${MTU}
    ip link set ${VETH0} up
}

validate_root_exec
retval=$?
if [ $retval != 0 ]; then
    test_exit $retval
fi

validate_veth_mod
retval=$?
if [ $retval != 0 ]; then
	echo "retval is: " $retval
	test_exit $retval
fi

validate_configs
setup_vethPairs

retval=$?
if [ $retval -ne 0 ]; then
	cleanup_exit ${VETH0} ${VETH1} ${NS1}
fi

echo "${VETH0}:${VETH1},${NS1}" > ${SPECFILE}

echo "Spec file created: ${SPECFILE}"

test_exit $retval
