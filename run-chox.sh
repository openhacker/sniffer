#! /bin/bash


# use filter= to change the default filter 
# filter=${filter:-tcp}


lan_name=chox-lan
wan_name=chox-wan
lan_mac=e0:91:f5:6a:78:de 
wan_mac=e0:91:f5:6a:78:df

if [ "$1" == "gdb" ]; 
then
	gdb -x gdbinit --args  ./chox  -c config.file -b 500 -q 50  -l $lan_name:$lan_mac -w $wan_name:$wan_mac

elif [ "$1" == valgrind ]; 
then
	 valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all -v  --log-file=valgrind.$$.log \
	 	./chox   -c config.file  -b 500 -q 50   -l $lan_name:$lan_mac -w $wan_name:$wan_mac
else
#	 chox   -c config.file  -b 500 -q 50  $CMD_LINE -l $lan_name:$lan_mac -w $wan_name:$wan_mac
	 ./chox   -c config.file  -b 500 -q 50   -l $lan_name:$lan_mac -w $wan_name:$wan_mac
fi
#	 valgrind --leak-check=full --show-leak-kinds=all -v  --vgdb-error=0  \
