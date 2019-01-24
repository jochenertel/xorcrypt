aestest: aestest.o aes.o
	gcc -Wall -o aestest aestest.o aes.o -lcrypto

aestest.o: aestest.c
	gcc -Wall -c aestest.c

aes.o: aes.c aes.h
	gcc -Wall -c aes.c

clean:
	rm -f *.o
	rm -f aestest

