#include <iostream>
#include <cstring>
#include <openssl/evp.h>

using namespace std;

const int STRING_LENGTH = 50;

/**
 * Сгенерировать ключ
 * @return сгенерированный ключ
*/
char *KeyGenerate()
{
    return (char *)EVP_chacha20();
}

/**
 * Зашифровать текст
 * @param key ключ генерации
 * @param string текст
 * @param result массив для зашифрованного текста
 * @param iv шифр текста
 * @return длина зашифрованного текста
*/
int Enc(const char *key, const char *string, char *result, unsigned char *iv)
{
    int length;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, iv);
    EVP_EncryptUpdate(ctx, (unsigned char *)result, &length, (unsigned char *)string,
                      strlen((char *)string));
    int resultLength = length;

    EVP_EncryptFinal_ex(ctx, (unsigned char *)result + length, &length);

    resultLength += length;

    EVP_CIPHER_CTX_free(ctx);

    return resultLength;
}

/**
 * Расшифровать текст
 * @param key ключ генерации
 * @param text зашифрованый текст
 * @param result массив для расшифрованного текста
 * @param textLength длина зашифрованного текста
 * @param iv шифр текста
 * @return длина рашифрованного текста
*/
int Dec(const char *key, const char *text, char *result, int textLength, unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, iv);

    int length;

    EVP_DecryptUpdate(ctx, (unsigned char *)result, &length, (unsigned char *)text, textLength);

    int decryptTextLength = length;

    EVP_DecryptFinal_ex(ctx, (unsigned char *)text + length, &length);

    decryptTextLength += length;

    EVP_CIPHER_CTX_free(ctx);

    return decryptTextLength;
}

int main()
{
    char *key = KeyGenerate(),
         *text = "Test text",
         encryptText[STRING_LENGTH],
         decryptText[STRING_LENGTH];
    unsigned char *iv = (unsigned char *)EVP_chacha20();

    cout << "Source Text: " << text << endl;
    int encryptTextLength = Enc(key, text, encryptText, iv);

    cout << "Encrypt Text: " << encryptText << endl;
    int decryptTextLength = Dec(key, encryptText, decryptText, encryptTextLength, iv);

    decryptText[decryptTextLength] = 0;
    cout << "Decrypt Text: " << decryptText << endl;

    return 0;
}
