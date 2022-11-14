#include <stdio.h>
#include <sys/random.h>
#include "core/crypto.h"
#include "ecc/ec.h"
#include "ecc/ec_curves.h"
#include "ecc/ecdsa.h"
#include "rng/yarrow.h"

// PRNG context
YarrowContext yarrowContext;

// Forward declarations
int generate_random_seed(uint8_t *seed, size_t *randSeedSize);

// This is the message to be signed.
unsigned char message[] = {0xF4, 0x5D, 0x55, 0xF3, 0x55, 0x51, 0xE9, 0x75, 0xD6,
                           0xA8, 0xDC, 0x7E, 0xA9, 0xF4, 0x88, 0x59,
                           0x39, 0x40, 0xCC, 0x75, 0x69, 0x4A, 0x27, 0x8F,
                           0x27, 0xE5, 0x78, 0xA1, 0x63, 0xD8, 0x39, 0xB3,
                           0x40, 0x40, 0x84, 0x18, 0x08, 0xCF, 0x9C, 0x58,
                           0xC9, 0xB8, 0x72, 0x8B, 0xF5, 0xF9, 0xCE, 0x8E,
                           0xE8, 0x11, 0xEA, 0x91, 0x71, 0x4F, 0x47, 0xBA,
                           0xB9, 0x2D, 0x0F, 0x6D, 0x5A, 0x26, 0xFC, 0xFE,
                           0xEA, 0x6C, 0xD9, 0x3B, 0x91, 0x0C, 0x0A, 0x2C,
                           0x96, 0x3E, 0x64, 0xEB, 0x18, 0x23, 0xF1, 0x02,
                           0x75, 0x3D, 0x41, 0xF0, 0x33, 0x59, 0x10, 0xAD,
                           0x3A, 0x97, 0x71, 0x04, 0xF1, 0xAA, 0xF6, 0xC3,
                           0x74, 0x27, 0x16, 0xA9, 0x75, 0x5D, 0x11, 0xB8,
                           0xEE, 0xD6, 0x90, 0x47, 0x7F, 0x44, 0x5C, 0x5D,
                           0x27, 0x20, 0x8B, 0x2E, 0x28, 0x43, 0x30, 0xFA,
                           0x3D, 0x30, 0x14, 0x23, 0xFA, 0x7F, 0x2D, 0x08,
                           0x6E, 0x0A, 0xD0, 0xB8, 0x92, 0xB9, 0xDB, 0x54,
                           0x4E, 0x45, 0x6D, 0x3F, 0x0D, 0xAB, 0x85, 0xD9,
                           0x53, 0xC1, 0x2D, 0x34, 0x0A, 0xA8, 0x73, 0xED,
                           0xA7, 0x27, 0xC8, 0xA6, 0x49, 0xDB, 0x7F, 0xA6,
                           0x37, 0x40, 0xE2, 0x5E, 0x9A, 0xF1, 0x53, 0x3B,
                           0x30, 0x7E, 0x61, 0x32, 0x99, 0x93, 0x11, 0x0E,
                           0x95, 0x19, 0x4E, 0x03, 0x93, 0x99, 0xC3, 0x82,
                           0x4D, 0x24, 0xC5, 0x1F, 0x22, 0xB2, 0x6B, 0xDE,
                           0x10, 0x24, 0xCD, 0x39, 0x59, 0x58, 0xA2, 0xDF,
                           0xEB, 0x48, 0x16, 0xA6, 0xE8, 0xAD, 0xED, 0xB5,
                           0x0B, 0x1F, 0x6B, 0x56, 0xD0, 0xB3, 0x06, 0x0F,
                           0xF0, 0xF1, 0xC4, 0xCB, 0x0D, 0x0E, 0x00, 0x1D,
                           0xD5, 0x9D, 0x73, 0xBE, 0x12};

int generate_random_seed(uint8_t *seed, size_t *randSeedSize)
{
    // Generatea CSPRNG Seed (32 bytes)
    // https://man7.org/linux/man-pages/man2/getrandom.2.html
    // getrandom() was introduced in version 3.17 of the Linux kernel.
    *randSeedSize = getrandom(seed, 32, GRND_RANDOM);
    if (*randSeedSize != 32)
    {
        // Incorrect seed length
        return ERROR_FAILURE;
    }

    return NO_ERROR;
}

int main(int argc, char *argv[])
{
    error_t error;
    size_t messageLen;
    uint8_t digest[64];

    EcDomainParameters params;
    EcPrivateKey privateKey;
    EcPublicKey publicKey;
    EcdsaSignature signature;

    Mpi r;
    Mpi t;

    uint8_t randSeed[32];
    size_t randSeedSize = 0;

    error = NO_ERROR;
    messageLen = sizeof(message);

    // Initialize EC domain parameters
    ecInitDomainParameters(&params);
    // Load EC domain parameters
    ecLoadDomainParameters(&params, SECP192R1_CURVE);
    // Initialize ECDSA private key
    ecInitPrivateKey(&privateKey);
    // Initialize ECDSA public key
    ecInitPublicKey(&publicKey);
    // Initialize ECDSA signature (calculated)
    ecdsaInitSignature(&signature);

    // Initialize multiple precision integers
    mpiInit(&r);
    mpiInit(&t);

    // start of exception handling block
    do
    {
        printf("Initializing CSPRNG...\n");
        error = generate_random_seed(randSeed, &randSeedSize);
        if (error)
        {
            printf("Error. Random seed initialization failed. (%d)\r\n", error);
            break;
        }

        // Initialize PRNG Algo
        error = yarrowInit(&yarrowContext);
        if (error)
        {
            printf("Error. CSPRNG initialization failed (%d)\r\n", error);
            break;
        }

        // Seed PRNG
        error = yarrowSeed(&yarrowContext, randSeed, randSeedSize);
        if (error)
        {
            printf("Error. Failed to seed CSPRNG (%d)\r\n", error);
            break;
        }
        printf("Done.\n");

        printf("Calculating digest of the message to be signed.\n");
        // Digest message
        error = sha256Compute(message, messageLen, digest);
        if (error)
        {
            printf("Error. Failed to digest message.\r\n");
            break;
        }
        printf("Done.\n");

        printf("Generating ECDSA key pair...\n");
        // ECDSA key pair generation
        error = ecdsaGenerateKeyPair(YARROW_PRNG_ALGO, &yarrowContext, &params,
                                     &privateKey, &publicKey);

        if (error)
        {
            printf("Error. Failed to generate ECDSA key pair.\r\n");
            break;
        }
        printf("Done.\n");

        printf("Generating ECDSA signature...\n");
        // ECDSA signature generation
        error = ecdsaGenerateSignature(YARROW_PRNG_ALGO, &yarrowContext, &params,
                                       &privateKey, digest, SHA256_DIGEST_SIZE, &signature);

        if (error)
        {
            printf("Error. Failed to generate ECDSA signature.\r\n");
            break;
        }
        printf("Done.\n");

        printf("Verifying ECDSA signature...\n");
        // ECDSA signature verification
        error = ecdsaVerifySignature(&params, &publicKey, digest,
                                     SHA256_DIGEST_SIZE, &signature);
        if (error)
        {
            printf("Error. Failed to verify ECDSA signature.\r\n");
            break;
        }
        printf("Done.\n");
        ecFreeDomainParameters(&params);

        printf("ECDSA Signature Generation/Verification Complete.\r\n");

        // end of exception handling block
    } while (0);

    // Release previously allocated resources
    ecFreeDomainParameters(&params);
    ecFreePrivateKey(&privateKey);
    ecFreePublicKey(&publicKey);
    ecdsaFreeSignature(&signature);
    mpiFree(&r);
    mpiFree(&t);

    return NO_ERROR;
}
