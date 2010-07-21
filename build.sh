#!/bin/bash

# This bash script tries to build the four triptools (if needed) and will test
# to ensure ./tripcode and ./sectrip produce the expected output.
# If you don't need testing, you can just use make, of course.


# Regular tripcode tool (tripcode)

echo -en "\033[2m"
make tripcode
echo -en "\033[0m"

if [ ! -f tripcode ]; then
    echo -e "\033[1;31mERROR\033[0m Couldn't build regular tripcode tool!"
else
    if [ "`./tripcode tea`" = "WokonZwxw2" -a \
         "`./tripcode 1fXzap//`" = "MhMRSATORI" -a \
         "`./tripcode 'a&b'`" = "vbZwEe8/SY" ]; then
        echo "Regular tripcode tool seems to work."
    else
        echo -e "\033[1;31mERROR\033[0m Regular tripcode tool did not produce" \
                "expected output."
    fi
fi


# Secure tripcode tool (sectrip)

echo -en "\033[2m"
make sectrip
echo -en "\033[0m"

if [ ! -f sectrip ]; then
    echo -e "\033[1;31mERROR\033[0m Couldn't build secure tripcode tool!"
else
    if [ "`./sectrip 'k!!!39@I'`" = "3O9pT+Xarn+zPxK" -a \
         "`./sectrip 'W!!$yJOE'`" = "ErikafwT59ifZua" ]; then
        echo "Secure tripcode tool seems to work."
    else
        echo -e "\033[1;31mERROR\033[0m Secure tripcode tool did not produce" \
                "expected output."
    fi
fi


# Regular tripfinder (tripfind)

echo -en "\033[2m"
make tripfind
echo -en "\033[0m"

if [ ! -f tripfind ]; then 
    echo -e "\033[1;31mERROR\033[0m Couldn't build regular tripfinder!"
fi


# Secure tripfinder (secfind)

echo -en "\033[2m"
make secfind
echo -en "\033[0m"

if [ ! -f secfind ]; then
    echo -e "\033[1;31mERROR\033[0m Couldn't build secure tripfinder!"
fi


# Regular tripfinder with regex (tripfind-regex)

echo -en "\033[2m"
make tripfind-regex
echo -en "\033[0m"

if [ ! -f tripfind-regex ]; then 
    echo -e "\033[1;31mERROR\033[0m Couldn't build regular regex tripfinder!"
fi


# Secure tripfinder (secfind)

echo -en "\033[2m"
make secfind-regex
echo -en "\033[0m"

if [ ! -f secfind-regex ]; then
    echo -e "\033[1;31mERROR\033[0m Couldn't build secure regex tripfinder!"
fi
