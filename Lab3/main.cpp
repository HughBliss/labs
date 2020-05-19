#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE 32
#define BLOCK_SIZE 16
#define SOURCE "mock"
#define ENCRYPTION_RESULT "encryption-result"
#define DECRYPTION_RESULT "decryption-result"

using namespace std;
/**
 * Зашифровать с помощью алгоритма AES
 * @param key ключ генерации
 * @param iv инициализирующий вектор
 * @param source исходный текст
 * @param result результат шифрования
*/
void aesEncrypt(unsigned char *key, unsigned char *iv, string &source, string &result) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_128_ctr(), key, iv);

    result.resize(source.size());
    int lengthresult = result.size();

    EVP_EncryptUpdate(ctx, (unsigned char *) &result[0], &lengthresult, (unsigned char *) &source[0],
                      source.size());
}

/**
 * Расшифровать с помощью алгоритма AES
 * @param key ключ генерации
 * @param iv инициализирующий вектор
 * @param source исходный текст
 * @param result результат дешифровки
*/
void aesDecrypt(unsigned char *key, unsigned char *iv, string &source, string &result) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_128_ctr(), key, iv);

    result.resize(source.size());
    int lengthresult = result.size();

    EVP_DecryptUpdate(ctx, (unsigned char *) &result[0], &lengthresult, (unsigned char *) &source[0],
                      source.size());
}

int main() {
    unsigned char key[KEY_SIZE], iv[BLOCK_SIZE];
    RAND_bytes(key, KEY_SIZE);
    RAND_bytes(iv, BLOCK_SIZE);

    ifstream inputFile(SOURCE);
    ofstream outputFile(ENCRYPTION_RESULT), cipherFile(DECRYPTION_RESULT);

    string sourceBuffer((istreambuf_iterator<char>(inputFile)), (istreambuf_iterator<char>())),
            outputText,
            cipherText;

    aesEncrypt(key, iv, sourceBuffer, cipherText);
    aesDecrypt(key, iv, cipherText, outputText);

    cipherFile << cipherText;
    outputFile << outputText;

    return 0;
}
