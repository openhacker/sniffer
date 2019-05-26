



#  OPT=-O3
CFLAGS=-g  -Wall ${OPT}

OBJS=main.o pcapreader.o

PROGS=chox 

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

install:
	cp chox /usr/local/bin

DEB_VERSION:=0.1-2
DEB_NAME:=chox-$(DEB_VERSION)

deb:	all
	-rm -rf ${DEB_NAME}
	mkdir ${DEB_NAME}
	cp -a DEBIAN ${DEB_NAME}
	mkdir -p ${DEB_NAME}/usr/local/bin
	cp  chox ${DEB_NAME}/usr/local/bin
	mkdir -p ${DEB_NAME}/usr/share/doc
	cp README LICENSE ${DEB_NAME}/usr/share/doc
	dpkg-deb --build ${DEB_NAME}
	
	
