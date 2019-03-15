#! /bin/bash


# use filter= to change the default filter 
filter="${filter:-tcp}"

if [ "$1" == "gdb" ]; 
then
	gdb -x .gdbinit --args  ./chox  -s -f "$filter" -l chox-lan:e0:91:f5:6a:78:de -w chox-wan:e0:91:f5:6a:78:df
elif [ "$1" == valgrind ]; 
then
	 valgrind --leak-check=full --show-leak-kinds=all -v  --log-file=valgrind.$$.log \
			./chox  -s    -f "$filter" -l chox-lan:e0:91:f5:6a:78:de -w chox-wan:e0:91:f5:6a:78:df
else
	 exec ./chox     -b 200 -f "$filter" -l chox-lan:e0:91:f5:6a:78:de -w chox-wan:e0:91:f5:6a:78:df
fi
