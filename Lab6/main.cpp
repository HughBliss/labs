#include <string>
#include <iostream>
#include "DiffieHellmanKeyGenerator.h"

int main(int argc, char *argv[])
{
    DiffieHellmanKeyGenerator alice, bob;

    EVP_PKEY *aliceKey = alice.generate();
    EVP_PKEY *bobKey = bob.generate();

    const std::string aliceShared = alice.derive(bobKey);
    const std::string bobShared = bob.derive(aliceKey);

    if (aliceShared == bobShared)
    {
        std::cout << " общий ключ Боба и Алисы совпадают\n";
    }
    else
    {
        std::cerr << " общий ключ Боба и Алисы несовпадают\n";
    }

    return 0;
}
