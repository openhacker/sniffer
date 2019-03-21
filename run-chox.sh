#! /bin/bash


# use filter= to change the default filter 
filter=${filter:-tcp}


lan_name=chox-lan
wan_name=chox-wan
lan_mac=e0:91:f5:6a:78:de 
wan_mac=e0:91:f5:6a:78:df

if [ "$1" == "gdb" ]; 
then
	gdb -x .gdbinit --args  ./chox  -s -f "$filter" -l chox-lan:e0:91:f5:6a:78:de -w chox-wan:e0:91:f5:6a:78:df
elif [ "$1" == valgrind ]; 
then
	 valgrind --leak-check=full --show-leak-kinds=all -v  --log-file=valgrind.$$.log \
			./chox  -s    -f "$filter" -l chox-lan:e0:91:f5:6a:78:de -w chox-wan:e0:91:f5:6a:78:df
else
	 ./chox  -m -c config.file -s  -b 500  -f "$filter" -l $lan_name:$lan_mac -w $wan_name:$wan_mac
fi
