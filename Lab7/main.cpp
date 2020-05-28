#include <string>
#include <iostream>
#include <openssl/rand.h>
#include <chrono>
#include "RSA.h"
#include "ECDSA.h"


std::string generateRandomString(size_t lambda)
{
    unsigned char *key = new unsigned char[lambda];
    const int generateResult = RAND_bytes(key, lambda);

    if (generateResult != 1)
    {
        std::cerr << "Generate key error: RAND_bytes function returned code " << generateResult << std::endl;
    }

    const std::string retVal = std::string(key, key + lambda / sizeof(unsigned char));
    delete[] key;

    return retVal;
}


int main()
{
    const std::string plainText = "Lorem ipsum dolor sit, amet consectetur adipisicing elit.";
    RSABenchmark rsaB;
    const bool rsaTestResult = rsaB.work(plainText);

    std::cout << "RSA Test: " << (rsaTestResult ? "Ok" : "Defeat") << std::endl;

    ECDSABenchmark ecdsaB;
    const bool ecdsaTestResult = ecdsaB.work(plainText);

    std::cout << "ECDSA Test: " << (ecdsaTestResult ? "Ok" : "Defeat") << std::endl;

    if (ecdsaTestResult && rsaTestResult)
    {
        //ecdsa test
        const auto ecdsaStart = std::chrono::steady_clock::now();
        for (size_t i = 0; i < 1000; i++)
        {
            const std::string message = generateRandomString(50);
            ecdsaB.work(message);
        }
        const auto ecdsaEnd = std::chrono::steady_clock::now();
        std::cout << "ECDSA Benchmark result: " << std::chrono::duration_cast<std::chrono::seconds>(ecdsaEnd - ecdsaStart).count() << std::endl;

        //rsa test
        const auto rsaStart = std::chrono::steady_clock::now();
        for (size_t i = 0; i < 1000; i++)
        {
            const std::string message = generateRandomString(50);
            rsaB.work(message);
        }
        const auto rsaEnd = std::chrono::steady_clock::now();
        std::cout << "RSA Benchmark result: " <<  std::chrono::duration_cast<std::chrono::seconds>(rsaEnd - rsaStart).count() << std::endl;
    }

    return 0;
}
