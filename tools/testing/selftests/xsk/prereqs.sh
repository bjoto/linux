#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

#ksft_skip exit status
#1: Internal error
#2: sysfs/debugfs not mount
#3: insert module fail when veth is a module
#4: Skip test including run as non-root user
#5: other reason such as veth.spec not found
#   -> implies init_veth.sh failed

GREEN='\033[0;92m'
RED='\033[0;31m'
NC='\033[0m'
STACK_LIM=131072

validate_root_exec()
{
	msg="skip all tests:"
	if [ $UID != 0 ]; then
		echo $msg must be run as root >&2
		return 4
	else
		return 0
	fi
}

validate_veth_mod()
{
	msg="skip all tests:"
	modprobe veth 2> /dev/null
	if [ $? != 0 ]; then
		echo $msg veth module not built >&2
		return 3
	else
		return 0
	fi
}

test_exit()
{
	retval=$1
	if [ $retval -ne 0 ]; then
		echo -e "$(basename $0): ${RED}FAIL${NC}"
	else
		echo -e "$(basename $0): ${GREEN}PASS${NC}"
	fi

	exit $retval
}


clear_configs()
{
	if [ $(ip netns show | grep $3 &>/dev/null; echo $?;) == 0 ]; then
	    [ $(ip netns exec $3 ip link show $2 &>/dev/null; echo $?;) == 0 ] &&
			{ echo "removing link $2"; ip netns exec $3 ip link del $2; }
        echo "removing ns $3"
        ip netns del $3
    fi
    #Once we del a veth pair node, the entire veth pair is removed,
	#this is just to be cautious just incase the NS
	#
    #does not exist then veth node inside NS won't get removed so we
	#explicitly remove it:
	[ $(ip link show $1 &>/dev/null; echo $?;) == 0 ] &&
		{ echo "removing link $1"; ip link del $1; }
}

cleanup_exit()
{
	echo "cleaning up..."
	clear_configs $1 $2 $3
}

check_iproute2()
{
	ip link help 2>&1 | grep -q "\s$1\s"
	retval=$?
	if [ $retval -ne 0 ]; then
		echo "Error unmet dependency: iproute2 not supported"
	    test_exit $retval
	fi
	return 0
}

validate_configs() {
    [ ! $(type -P ip) ] && { echo "'ip' not found. Skipping tests."; test_exit 1; }
    check_iproute2
}

vethXDPgeneric() {
	ip link set dev $1 xdpdrv off
	ip netns exec $3 ip link set dev $2 xdpdrv off
}

vethXDPnative() {
	ip link set dev $1 xdpgeneric off
	ip netns exec $3 ip link set dev $2 xdpgeneric off
}

setStackLimit() {
    if [ $(ulimit -s) == "unlimited" ]; then
        echo "Stack ulimit:" $(ulimit -s)
    elif [ $(ulimit -s) -ge $STACK_LIM ]; then
        echo "Stack ulimit:" $(ulimit -s)
    else
        ulimit -S -s $STACK_LIM
        echo "Modified stack ulimit:" $STACK_LIM
    fi
}

