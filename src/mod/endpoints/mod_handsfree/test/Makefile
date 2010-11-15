CC=gcc
CFLAGS=-Wall 
GLIB_CFLAGS=-I/usr/include/glib-2.0 -I/usr/include/dbus-1.0 -I/usr/lib/glib-2.0/include
LDFLAGS=-lrt

#all: audioclient list-names list-modems
all: audioclient 

audioclient.o: audioclient.c ipc.h
	$(CC) $(CFLAGS) -c audioclient.c -o audioclient.o

ipc.o: ipc.c ipc.h
	$(CC) $(CFLAGS) -c ipc.c -o ipc.o 

audioclient: audioclient.o ipc.o
	$(CC) $(LDFLAGS) audioclient.o ipc.o -o audioclient

list-names.o: list-names.c
	$(CC) $(CFLAGS) $(GLIB_CFLAGS) -c list-names.c -o list-names.o
	
list-names: list-names.o
	$(CC) -ldbus-glib-1 list-names.o -o list-names

list-modems.o: list-modems.c
	$(CC) $(CFLAGS) $(GLIB_CFLAGS) -c list-modems.c -o list-modems.o
	
list-modems: list-modems.o
	$(CC) -ldbus-glib-1 list-modems.o -o list-modems
	
clean:
	rm -rf audioclient list-names list-modems *.o
	
.PHONY: clean

