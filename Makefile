CXX       = g++
OPT       = -O2
FLAGS     = $(OPT) -ansi


TOPDIR  := $(shell /bin/pwd)

THINGS =  giants.o sha1.o xboxlib.o xbedump.o  xbevalidate.o main.o 

all: clean xbe

%.o	: %.c
	${CXX} ${FLAGS} -o $@ -c $<

xbe: ${THINGS} ${CRYPTOLIB}
	${CXX} -o $@ -lm ${THINGS} 
clean:
	-rm -f *.o  xbe core
        