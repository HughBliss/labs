#ifndef DIFFIE_HELLMAN_KEY_GENERATOR_H__
#define DIFFIE_HELLMAN_KEY_GENERATOR_H__

#include <openssl/evp.h>
#include <string>

class DiffieHellmanKeyGenerator
{
public:
    DiffieHellmanKeyGenerator();

    EVP_PKEY *generate();
    std::string derive(EVP_PKEY *peerkey);

private:
    void handleErrors();

private:
    EVP_PKEY *pkey;
};

#endif // !DIFFIE_HELLMAN_KEY_GENERATOR_H__
