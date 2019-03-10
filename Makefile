



CFLAGS=-g  -Wall

OBJS=main.o pcapreader.o

PROGS=chox pcapreader capture

all:	${PROGS}
chox:	$(OBJS)
	$(CC) -o $@ $^ -g 

pcapreader: pcapreader.c
	${CC} -DDEBUG -o $@ $^ ${CFLAGS}

capture:	capture.o
	${CC} -o $@ $^  -lpcap

clean:
	-rm ${PROGS}
	-rm *.o
