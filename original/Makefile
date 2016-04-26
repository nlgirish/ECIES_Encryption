all: hello

hello: example.o ecies.o keys.o secure.o
	gcc example.o ecies.o keys.o secure.o -o hello -lssl -lcrypto

example.o: example.c
	gcc -c example.c

ecies.o: ecies.c
	gcc -c ecies.c

keys.o: keys.c
	gcc -c keys.c

secure.o: secure.c
	gcc -c secure.c

clean:
	rm hello *.o

