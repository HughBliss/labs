OPENSSLLIB = -L/usr/local/opt/openssl@1.1/lib

lab6: DiffieHellmanKeyGenerator.o main.o
	gcc DiffieHellmanKeyGenerator.o main.o -o lab6 -lstdc++ -lssl -lcrypto -std=c++0x
DiffieHellmanKeyGenerator.o: DiffieHellmanKeyGenerator.cpp DiffieHellmanKeyGenerator.h
	gcc -c DiffieHellmanKeyGenerator.cpp -std=c++0x
main.o: main.cpp DiffieHellmanKeyGenerator.h
	gcc -c main.cpp -std=c++0x

clean:
	rm -f lab6 DiffieHellmanKeyGenerator.o main.o
install:
	cp lab6 /usr/local/bin/lab6
uninstall:
	rm -f /usr/local/bin/lab6
