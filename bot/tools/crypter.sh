#!/bin/bash

if [[ $# != 1 ]] ; then
	printf "Usage:\n\t$0 [filename]\n"
	exit
fi

if ! ./genfun.exe $1; then
	exit
fi

echo "Done"
