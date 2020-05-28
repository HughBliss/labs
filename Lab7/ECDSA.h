#ifndef ECDSA_H__
#define ECDSA_H__

#include <openssl/pem.h>
#include <string>

class ECDSABenchmark
{
public:
    bool work(const std::string &plainText);

private:
    void generateKey();
    void signMessage(const std::string &priv_key_file_path, const unsigned char *buff, int buff_len, std::string &sig);
    bool verifySignature(const std::string &pub_key_file_path, const unsigned char *buff, size_t buff_len, const std::string &sig);
};

#endif
