#!/bin/bash

if [$1 == ""]
then {
	PWD=/usr/driver/asf/min
} else {
	PWD=/usr/driver/asf/$1
} fi

myvar=`lsmod`
myvar2=asf
if [ "`echo "$myvar" | grep "$myvar2"`" ]
then {
	rmmod asfctrl_ipsec
	rmmod asfctrl
	rmmod asfipsec
	rmmod asf
} fi

CMD=/sbin/insmod
$CMD $PWD/asf.ko
$CMD $PWD/asfipsec.ko
$CMD $PWD/asfctrl.ko
$CMD $PWD/asfctrl_ipsec.ko
