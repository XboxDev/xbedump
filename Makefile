CXX       = g++
OPT       = -O -g
FLAGS     = $(OPT) -ansi -W -Wall -L. -I /usr/local/ssl/include
#CRYPTOLIB  = /usr/local/ssl/lib/libcrypto.a
CRYPTOLIB  = /usr/lib/libcrypto.a

THINGS =  xboxlib.o xbedump.o  xbevalidate.o main.o

all: xbe

%.o	: %.c
	${CXX} ${FLAGS} -o $@ -c $<

xbe: ${THINGS} ${CRYPTOLIB}
	gcc -o $@ ${THINGS} ${CRYPTOLIB}
clean:
	-rm -f *.o  xbe core

