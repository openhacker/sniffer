



#  OPT=-O3
CFLAGS=-g  -Wall ${OPT}

OBJS=main.o pcapreader.o

ifdef MCHECK
MCHECK_LIB=-lmcheck
endif

PROGS=chox 

all:	${PROGS}
chox:	$(OBJS)
	$(CC) -o $@ $^ -g   ${MCHECK_LIB}

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
	
	
