#!/bin/bash

function wait4proxmark {
	echo >&2 "Waiting for Proxmark to appear..."
	while true; do
		PM3=$(ls /dev/pm3-* /dev/cu.usbmodem* 2>/dev/null | head -1)
		if [[ $PM3 != "" ]]; then
			#echo >&2 -e "Found proxmark on $(ls /dev/pm3-* /dev/cu.usbmodem* 2>/dev/null | head -1)\n"
			break
		fi
		sleep .1
	done
	echo $PM3
}

# flash bootroom & system image
client/flasher $(wait4proxmark) -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf 

