



CFLAGS=-g  -Wall

OBJS=main.o pcapreader.o

PROGS=chox pcapreader

all:	${PROGS}
chox:	$(OBJS)
	$(CC) -o $@ $^ -g 

pcapreader: pcapreader.c
	${CC} -DDEBUG -o $@ $^ ${CFLAGS}

clean:
	-rm ${PROGS}
	-rm *.o
