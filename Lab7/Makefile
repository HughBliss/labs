lab7: ECDSA.o RSA.o main.o
	gcc -std=c++11 ECDSA.o RSA.o main.o -o lab7 -lstdc++ -lcrypto -lssl
ECDSA.o: ECDSA.cpp ECDSA.h
	gcc -std=c++11 -c ECDSA.cpp
RSA.o: RSA.cpp RSA.h
	gcc -std=c++11 -c RSA.cpp
main.o: main.cpp ECDSA.h RSA.h
	gcc -std=c++11 -c main.cpp

clean:
	rm -f lab7 ECDSA.o RSA.o main.o
install:
	cp lab7 /usr/local/bin/lab7
uninstall:
	rm -f /usr/local/bin/lab7
