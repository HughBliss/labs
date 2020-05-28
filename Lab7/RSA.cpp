#include "RSA.h"

#include <openssl/err.h>
#include <fstream>
#include <cstring>

const int kKeyBits = 3072;
const char kPublic[] = "public.pem";
const char kPrivate[] = "private.pem";


bool RSABenchmark::work(const std::string &plainText)
{
    char *signedMessage;

    generateKey();

    std::ifstream file(kPublic);
    const std::string pkey((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
    file.close();

    std::ifstream ffile(kPrivate);
    const std::string prkey((std::istreambuf_iterator<char>(ffile)),
        std::istreambuf_iterator<char>());
    ffile.close();


    signedMessage = signMessage(prkey, plainText);
    size_t decodeLength = calcDecodeLength(signedMessage);
    unsigned char * buf = new unsigned char[decodeLength];
    Base64Decode(signedMessage, &buf, &decodeLength);

    const bool retVal = verifySignature(pkey, plainText, signedMessage);
    delete[] buf;

    return retVal;
}


bool RSABenchmark::generateKey()
{
    int ret = 0;
    RSA *r = nullptr;
    BIGNUM *bne = nullptr;
    BIO *bp_public = nullptr, *bp_private = nullptr;

    const unsigned long e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();

    if (BN_set_word(bne, e) == 1)
    {
        r = RSA_new();

        if (RSA_generate_key_ex(r, kKeyBits, bne, NULL) == 1)
        {
            // 2. save public key
            bp_public = BIO_new_file(kPublic, "w+");

            if (PEM_write_bio_RSAPublicKey(bp_public, r) == 1)
            {
                // 3. save private key
                bp_private = BIO_new_file(kPrivate, "w+");
                ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
            }
        }
    }

    // 4. free

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

    return (ret == 1);
}


RSA* RSABenchmark::createPrivateRSA(const std::string &key)
{
    RSA *rsa = nullptr;
    const char *c_string = key.c_str();
    BIO *keybio = BIO_new_mem_buf((void*)c_string, -1);

    if (keybio)
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }

    if (!rsa)
    {
        ERR_print_errors_fp(stderr);
    }

    return rsa;
}


bool RSABenchmark::RSASign(RSA *rsa, const unsigned char *Msg, size_t MsgLen, unsigned char **EncMsg, size_t *MsgLenEnc)
{
    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY* priKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);

    if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0)
    {
        return false;
    }

    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0)
    {
        return false;
    }

    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0)
    {
        return false;
    }

    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);

    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0)
    {
        return false;
    }

    EVP_MD_CTX_cleanup(m_RSASignCtx); //in other versions may be EVP_MD_CTX_free

    return true;
}


void RSABenchmark::Base64Encode(const unsigned char *buffer, size_t length, char **base64Text)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *base64Text = (*bufferPtr).data;
}


char* RSABenchmark::signMessage(const std::string &privateKey, const std::string &plainText)
{
    RSA* privateRSA = createPrivateRSA(privateKey);
    unsigned char* encMessage;
    char* base64Text;
    size_t encMessageLength;
    RSASign(privateRSA, (unsigned char*)plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
    Base64Encode(encMessage, encMessageLength, &base64Text);
    free(encMessage);

    return base64Text;
}


size_t RSABenchmark::calcDecodeLength(const char* b64input)
{
    size_t len = std::strlen(b64input), padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are '='
    {
        padding = 2;
    }
    else if (b64input[len - 1] == '=') //last char is '='
    {
        padding = 1;
    }

    return (len * 3) / 4 - padding;
}


void RSABenchmark::Base64Decode(char *b64message, unsigned char **buffer, size_t *length)
{
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, *buffer, std::strlen(b64message));
    BIO_free_all(bio);
}


RSA* RSABenchmark::createPublicRSA(const std::string &key)
{
    RSA *rsa = NULL;
    BIO *keybio;
    const char* c_string = key.c_str();
    keybio = BIO_new_mem_buf((void*)c_string, -1);

    if (keybio)
    {
        rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    }

    if (!rsa)
    {
        ERR_print_errors_fp(stderr);
    }

    return rsa;
}

bool RSABenchmark::RSAVerifySignature(RSA *rsa, unsigned char *MsgHash, size_t MsgHashLen, const char *Msg, size_t MsgLen, bool *Authentic)
{
    *Authentic = false;
    EVP_PKEY* pubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

    if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0)
    {
        return false;
    }

    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0)
    {
        return false;
    }

    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);

    if (AuthStatus == 1)
    {
        *Authentic = true;
        EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
        return true;
    }
    else if (AuthStatus == 0)
    {
        *Authentic = false;
        EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
        return true;
    }
    else
    {
        *Authentic = false;
        EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
        return false;
    }
}

bool RSABenchmark::verifySignature(const std::string &publicKey, std::string plainText, char* signatureBase64)
{
    RSA* publicRSA = createPublicRSA(publicKey);
    unsigned char* encMessage;
    size_t encMessageLength;
    bool authentic;
    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
    bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);

    return result & authentic;
}
