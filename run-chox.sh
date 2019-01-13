#! /bin/bash


if [ "$1" == "gdb" ]; 
then
	gdb --args  ./chox  -s -l chox-lan:e0:91:f5:6a:78:de -w chox-wan:e0:91:f4:6a:79:df
else
	 exec ./chox   -l chox-lan:e0:91:f5:6a:78:de -w chox-wan:e0:91:f4:6a:79:df
fi
