#ifndef RSA_H__
#define RSA_H__

#include <openssl/pem.h>
#include <string>

class RSABenchmark
{
public:
    bool work(const std::string &plainText);

private:
    bool generateKey();
    RSA *createPrivateRSA(const std::string &key);
    bool RSASign(RSA * rsa, const unsigned char *Msg, size_t MsgLen, unsigned char **EncMsg, size_t *MsgLenEnc);
    void Base64Encode(const unsigned char *buffer, size_t length, char **base64Text);
    char *signMessage(const std::string &privateKey, const std::string &plainText);
    size_t calcDecodeLength(const char *b64input);
    void Base64Decode(char *b64message, unsigned char **buffer, size_t *length);
    RSA *createPublicRSA(const std::string &key);
    bool RSAVerifySignature(RSA *rsa, unsigned char *MsgHash, size_t MsgHashLen, const char *Msg, size_t MsgLen, bool *Authentic);
    bool verifySignature(const std::string &publicKey, std::string plainText, char *signatureBase64);
};


#endif
