#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE 32
#define BLOCK_SIZE 16
#define SOURCE "mock"
#define GCM_DECRYPTION_RESULT "gsm-decryption-result"
#define GCM_ENCRYPTION_RESULT "gsm-encryption-result"
#define CCM_DECRYPTION_RESULT "ccm-decryption-result"
#define CCM_ENCRYPTION_RESULT "ccm-encryption-result"

using namespace std;

/**
 * Зашифровать алгоритмом GCM
 * @param source исходный текст
 * @param aad дополнительные данные
 * @param key ключ
 * @param iv инициализирующий вектор
 * @param ivLength длина инициализирующего вектора
 * @param result Результат шифрования
*/
void gcmEncrypt(string &source,
                string &aad,
                unsigned char *key,
                unsigned char *iv,
                int ivLength,
                string &result)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    result.resize(source.size());
    int lengthresult = result.size();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, NULL, &lengthresult, (unsigned char *) &aad, aad.size());
    EVP_EncryptUpdate(ctx, (unsigned char *) &result[0], &lengthresult, (unsigned char *) &source[0], source.size());
}


/**
 * Расшифровать алгоритмом GCM
 * @param source исходный текст
 * @param aad дополнительные данные
 * @param key ключ
 * @param iv инициализирующий вектор
 * @param ivLength длина инициализирующего вектора
 * @param result Результат дешифровки
*/
void gcmDecrypt(string &source,
                 string &aad,
                 unsigned char *key,
                 unsigned char *iv,
                 int ivLength,
                 string &result)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    result.resize(source.size());
    int lengthresult = result.size();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, NULL, &lengthresult, (unsigned char *) &aad, aad.size());
    EVP_DecryptUpdate(ctx, (unsigned char *) &result[0], &lengthresult, (unsigned char *) &source[0], source.size());
}

/**
 * Зашифровать алгоритмом CCM
 * @param source исходный текст
 * @param aad дополнительные данные
 * @param key ключ
 * @param iv инициализирующий вектор
 * @param ivLength длина инициализирующего вектора
 * @param result Результат шифрования
*/
void ccmEncrypt(string &source,
                string &aad,
                unsigned char *key,
                unsigned char *iv,
                int ivLength,
                string &result)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    result.resize(source.size());
    int lengthresult = result.size();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, NULL, &lengthresult, (unsigned char *) &aad, aad.size());
    EVP_EncryptUpdate(ctx, (unsigned char *) &result[0], &lengthresult, (unsigned char *) &source[0], source.size());
}

/**
 * Расшифровать алгоритмом CCM
 * @param source исходный текст
 * @param aad дополнительные данные
 * @param key ключ
 * @param iv инициализирующий вектор
 * @param ivLength длина инициализирующего вектора
 * @param result Результат дешифровки
*/
void ccmDecrypt(string &source,
                string &aad,
                unsigned char *key,
                unsigned char *iv,
                int ivLength,
                string &result)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    result.resize(source.size());
    int lengthresult = result.size();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, NULL, &lengthresult, (unsigned char *) &aad, aad.size());
    EVP_DecryptUpdate(ctx, (unsigned char *) &result[0], &lengthresult, (unsigned char *) &source[0], source.size());
}

int main() {
    unsigned char key[KEY_SIZE], iv[BLOCK_SIZE];
    RAND_bytes(key, KEY_SIZE);
    RAND_bytes(iv, BLOCK_SIZE);
    string aad = "no secret";

    ifstream source(SOURCE);
    ofstream GcmDecryptionResult(GCM_DECRYPTION_RESULT),
            GcmEncryptionResult(GCM_ENCRYPTION_RESULT),
            CcmDecryptionResult(CCM_DECRYPTION_RESULT),
            CcmEncryptionResult(CCM_ENCRYPTION_RESULT);

    string inputTextBuffer((istreambuf_iterator<char>(source)), (istreambuf_iterator<char>())),
            outputText,
            cipherText;

    gcmEncrypt(inputTextBuffer, aad, key, iv, BLOCK_SIZE, cipherText);
    gcmDecrypt(cipherText, aad, key, iv, BLOCK_SIZE, outputText);
    GcmEncryptionResult << cipherText;
    GcmDecryptionResult << outputText;

    ccmEncrypt(inputTextBuffer, aad, key, iv, BLOCK_SIZE, cipherText);
    ccmDecrypt(cipherText, aad, key, iv, BLOCK_SIZE, outputText);
    CcmEncryptionResult << cipherText;
    CcmDecryptionResult << outputText;

    return 0;
}
