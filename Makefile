CXX       = gcc
OPT       = -O -g
FLAGS     = $(OPT) -W -Wall -L. -I /usr/local/ssl/include
CRYPTOLIB  = /usr/local/ssl/lib/libcrypto.a

THINGS =  xboxlib.o xbedump.o xbevalidate.o main.o

all: xbedump

%.o	: %.c
	${CXX} ${FLAGS} -o $@ -c $<

xbedump: ${THINGS} ${CRYPTOLIB}
	gcc -o $@ ${THINGS} ${CRYPTOLIB}
clean:
	-rm -f *.o  xbedump *~

