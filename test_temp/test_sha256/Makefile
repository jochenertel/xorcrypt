shatest: shatest.o sha256.o
	gcc -Wall -o shatest shatest.o sha256.o -lcrypto

shatest.o: shatest.c
	gcc -Wall -c shatest.c

sha256.o: sha256.c sha256.h
	gcc -Wall -c sha256.c

clean:
	rm -f *.o
	rm -f shatest

