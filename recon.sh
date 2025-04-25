#!/bin/bash

TARGET=""

print_help() {
	echo "Use: $0 [-t target] [-h]"
	echo
	echo " -t 	Target"
	echo " -h 	Show help site"
}

while getopts ":t:h" opt; do
	case $opt in
		t)
			TARGET=$OPTARG
			;;
		h)
			print_help
			exit 0
			;;
	esac
done

dnsenum $TARGET | awk '/Name Servers:/,/^$/'
