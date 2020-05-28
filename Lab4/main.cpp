#include <iostream>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE 32
#define BLOCK_SIZE 16

using namespace std;

/**
 * получить tag
 * @param source исходное сообщение
 * @param key ключ
 * @return tag
*/
unsigned char *encryptMessage(unsigned char *source, unsigned char *key) {
    unsigned char input[BLOCK_SIZE],
            output[BLOCK_SIZE];
    int length = 0,
        outputLength = 0,
        inputLength;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, nullptr);

    while (true) {
        inputLength = 0;
        for (int i = length; i < length + BLOCK_SIZE; i++) {
            if (i >= strlen((char *) source)) {
                break;
            }
            input[i - length] = (unsigned char) source[i];
            inputLength++;
        }
        length += inputLength;
        if (inputLength < BLOCK_SIZE) {
            break;
        }
        EVP_CipherUpdate(ctx, output, &outputLength, input, inputLength);
    }

    auto *tag = (unsigned char *) malloc(outputLength);
    memcpy(tag, output, outputLength);

    return tag;
}

/**
 * сгенерировать сообщение M
 * @param source исходное сообщение
 * @param key ключ
 * @return сообщение M'
*/
unsigned char *generateMessage(const unsigned char *source, const unsigned char *tag) {
    string sourceChange(2 * BLOCK_SIZE, ' ');

    for (int i = 0; i < 2 * BLOCK_SIZE; i++) {
        if (i < BLOCK_SIZE) {
            sourceChange[i] = (unsigned char) (source[i]);
        } else {
            sourceChange[i] = (unsigned char) (source[i - BLOCK_SIZE] ^ tag[i - BLOCK_SIZE]);
        }
    }

    auto *result = (unsigned char *) malloc(sourceChange.length() + 1);
    strcpy((char *) result, sourceChange.c_str());

    return result;
}

/**
 * Верифицировать сообщение
 * @param source исходное сообщение
 * @param key ключ
 * @param tag tag
 * @return сообщение о результате верификации
 *
*/
const char *verifyMessage(unsigned char *source, unsigned char *key, unsigned char *tag) {
    return memcmp(tag, encryptMessage(source, key), sizeof(&tag)) != 0 ? "is incorrect" : "is correct";
}

int main() {
    unsigned char key[KEY_SIZE];
    RAND_bytes(key, KEY_SIZE);
    unsigned char *message = (unsigned char *)"Artur Maxyutov",
                  *tag = encryptMessage(message, key),
                  *message2 = generateMessage(message, tag);

    cout << "Message: " << message << endl;
    cout << "Tag: " << tag << endl;
    cout << "Message': " << message2 << endl;
    cout << "Message " << verifyMessage(message, key, tag) << endl;
    cout << "Message' " << verifyMessage(message2, key, tag) << endl;

    return 0;
}
