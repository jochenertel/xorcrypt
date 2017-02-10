xorcrypt: xorcrypt.o
	gcc -Wall -o xorcrypt xorcrypt.o -lcrypto

xorcrypt.o: xorcrypt.c
	gcc -Wall -c xorcrypt.c

clean:
	rm -f *.o
	rm -f xorcrypt

