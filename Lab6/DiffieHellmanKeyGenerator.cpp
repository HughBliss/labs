#include "DiffieHellmanKeyGenerator.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>

DiffieHellmanKeyGenerator::DiffieHellmanKeyGenerator()
    : pkey(nullptr)
{
}

//generate key. key will be returned (for move to recipient) and stored in class member 'pkey' for deriving
EVP_PKEY *DiffieHellmanKeyGenerator::generate()
{
    EVP_PKEY_CTX *pctx, *kctx;
    EVP_PKEY *params = NULL;

    /* Create the context for parameter generation */
    if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
        handleErrors();

    /* Initialise the parameter generation */
    if (1 != EVP_PKEY_paramgen_init(pctx))
        handleErrors();

    /* We're going to use the ANSI X9.62 Prime 256v1 curve */
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1))
        handleErrors();

    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params))
        handleErrors();

    /* Create the context for the key generation */
    if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL)))
        handleErrors();

    /* Generate the key */
    if (1 != EVP_PKEY_keygen_init(kctx))
        handleErrors();
    if (1 != EVP_PKEY_keygen(kctx, &pkey))
        handleErrors();

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);

    return pkey;
}

//derive shared secret. peerkey - key of other participant
std::string DiffieHellmanKeyGenerator::derive(EVP_PKEY *peerkey)
{
    EVP_PKEY_CTX *ctx;
    unsigned char *secret;
    size_t secret_len;

    /* Create the context for the shared secret derivation */
    if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
        handleErrors();

    /* Initialise */
    if (1 != EVP_PKEY_derive_init(ctx))
        handleErrors();

    /* Provide the peer public key */
    if (1 != EVP_PKEY_derive_set_peer(ctx, peerkey))
        handleErrors();

    /* Determine buffer length for shared secret */
    if (1 != EVP_PKEY_derive(ctx, NULL, &secret_len))
        handleErrors();

    /* Create the buffer */
    if (NULL == (secret = reinterpret_cast<unsigned char *>(OPENSSL_malloc(secret_len))))
        handleErrors();

    /* Derive the shared secret */
    if (1 != (EVP_PKEY_derive(ctx, secret, &secret_len)))
        handleErrors();

    const std::string retVal = std::string(secret, secret + secret_len / sizeof(unsigned char));
    OPENSSL_free(secret);
    EVP_PKEY_CTX_free(ctx);

    return retVal;
}

//print last error info and abort. called if some openssl function returned not 1 (not success)
void DiffieHellmanKeyGenerator::handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}
