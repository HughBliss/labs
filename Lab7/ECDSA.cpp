#include "ECDSA.h"
#include <cassert>
#include <openssl/err.h>

#if (defined _WIN64 || defined _WIN32)
#include <openssl/applink.c>
#endif


const std::string kPublic = "ec.public_key.pem";
const std::string kPrivate = "ec.private_key.pem";


bool ECDSABenchmark::work(const std::string &plainText)
{
    generateKey();
    std::string sig;
    signMessage(kPrivate, (unsigned char*)plainText.c_str(), plainText.size(), sig);

    return verifySignature(kPublic, (unsigned char*)plainText.c_str(), plainText.size(), sig);
}


void ECDSABenchmark::generateKey()
{
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //256 bit curve
    assert(1 == EC_KEY_generate_key(ec_key));
    assert(1 == EC_KEY_check_key(ec_key));

    BIO * bio = BIO_new_fp(stdout, 0);
    BIO_free(bio);

    {
        FILE *f = fopen(kPublic.c_str(), "w");
        PEM_write_EC_PUBKEY(f, ec_key);
        fclose(f);
    }

    {
        FILE *f = fopen(kPrivate.c_str(), "w");
        PEM_write_ECPrivateKey(f, ec_key, NULL, NULL, 0, NULL, NULL);
        fclose(f);
    }

    EC_KEY_free(ec_key);
}


void ECDSABenchmark::signMessage(const std::string &priv_key_file_path, const unsigned char *buff, int buff_len, std::string &sig)
{
    FILE *f = fopen(priv_key_file_path.c_str(), "r");
    EC_KEY *ec_key = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    assert(1 == EC_KEY_check_key(ec_key));

    EVP_PKEY * key = EVP_PKEY_new();
    assert(1 == EVP_PKEY_assign_EC_KEY(key, ec_key));

    EVP_PKEY_CTX * key_ctx = EVP_PKEY_CTX_new(key, NULL);
    assert(1 == EVP_PKEY_sign_init(key_ctx));
    assert(1 == EVP_PKEY_CTX_set_signature_md(key_ctx, EVP_sha256()));
    size_t sig_len = 0;

    assert(1 == EVP_PKEY_sign(key_ctx, NULL, &sig_len, buff, buff_len));
    sig.assign(sig_len, 0);
    assert(1 == EVP_PKEY_sign(key_ctx, (unsigned char *)&sig[0], &sig_len, buff, buff_len));

    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(key);
}


bool ECDSABenchmark::verifySignature(const std::string &pub_key_file_path, const unsigned char *buff, size_t buff_len, const std::string &sig)
{
    FILE *f = fopen(pub_key_file_path.c_str(), "r");
    EC_KEY *ec_key = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);

    EVP_PKEY *key = EVP_PKEY_new();
    assert(1 == EVP_PKEY_assign_EC_KEY(key, ec_key));

    EVP_PKEY_CTX * key_ctx = EVP_PKEY_CTX_new(key, NULL);

    assert(1 == EVP_PKEY_verify_init(key_ctx));
    assert(1 == EVP_PKEY_CTX_set_signature_md(key_ctx, EVP_sha256()));
    size_t sig_len = 0;

    const int ret = EVP_PKEY_verify(key_ctx, (unsigned char *)&sig[0], sig.size(), buff, buff_len);

    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(key);

    return ret;
}
