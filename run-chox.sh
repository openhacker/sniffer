#! /bin/bash


# use filter= to change the default filter 
filter="${filter:-tcp}"

lan_name=chox-lan
if [ "$1" == "gdb" ]; 
then
	gdb -x .gdbinit --args  ./chox  -s -f "$filter" -l chox-lan:e0:91:f5:6a:78:de -w chox-wan:e0:91:f5:6a:78:df
elif [ "$1" == valgrind ]; 
then
	 valgrind --leak-check=full --show-leak-kinds=all -v  --log-file=valgrind.$$.log \
			./chox  -s    -f "$filter" -l chox-lan:e0:91:f5:6a:78:de -w chox-wan:e0:91:f5:6a:78:df
else
	 exec ./chox -m    -b 500  -f "$filter" -l $lan_name:e0:91:f5:6a:78:de -w chox-wan:e0:91:f5:6a:78:df
fi
