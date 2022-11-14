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
error_t trngGetRandomData(uint8_t *data, size_t length);
error_t signature_generation();
error_t signature_verification();

error_t trngGetRandomData(uint8_t *data, size_t length)
{
    // Generatea CSPRNG Seed (32 bytes)
    // https://man7.org/linux/man-pages/man2/getrandom.2.html
    // getrandom() was introduced in version 3.17 of the Linux kernel.
    ssize_t len;
    len = getrandom(data, length, GRND_RANDOM);

    if (len != length)
    {
        // Incorrect seed length
        return ERROR_FAILURE;
    }

    return NO_ERROR;
}

int init_crypto_rng(uint8_t *seed, size_t length)
{
    uint_t i;
    uint32_t value;
    error_t error;

    //...Generate a random seed (32 bytes) using your hardware here...
    error = trngGetRandomData(seed, length);

    if (error)
    {
        // Debug message
        printf("Failed to get random data!\r\n");
    }

    // PRNG initialization
    error = yarrowInit(&yarrowContext);
    // Any error to report?
    if (error)
    {
        // Debug message
        printf("Failed to initialize PRNG!\r\n");
    }

    // Properly seed the PRNG
    error = yarrowSeed(&yarrowContext, seed, length);
    // Any error to report?
    if (error)
    {
        // Debug message
        printf("Failed to seed PRNG!\r\n");
    }

    return error;
}

error_t signature_generation()
{
    error_t  error;
    EcDomainParameters params;
    EcPrivateKey privateKey;
    EcdsaSignature signature;
    uint8_t digest[64];

    //Message to be signed
    char_t message[] = "test";

    // ECDSA private key
    uint8_t d[32] = {
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
        0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21};

    // Resulting ECDSA signature
    uint8_t r[32];
    uint8_t s[32];

    // Initialize EC domain parameters
    ecInitDomainParameters(&params);
    // Initialize ECDSA private key
    ecInitPrivateKey(&privateKey);
    // Initialize ECDSA signature
    ecdsaInitSignature(&signature);

    // Load EC domain parameters
    error = ecLoadDomainParameters(&params, SECP256R1_CURVE);

    // Read ECDSA private key
    if (!error)
    {
        error = mpiImport(&privateKey.d, d, 32, MPI_FORMAT_BIG_ENDIAN);
    }

    // Digest the message
    if (!error)
    {
        error = sha256Compute(message, strlen(message), digest);
    }

    // Check status code
    if (!error)
    {
        // Debug message
        printf("Generating ECDSA signature...\r\n");

        // ECDSA signature generation
        error = ecdsaGenerateSignature(YARROW_PRNG_ALGO, &yarrowContext, &params,
                                       &privateKey, digest, SHA256_DIGEST_SIZE, &signature);
    }

    // Export the R and S integers of the ECDSA signature
    if (!error)
    {
        error = mpiExport(&signature.r, r, 32, MPI_FORMAT_BIG_ENDIAN);
    }

    if (!error)
    {
        error = mpiExport(&signature.s, s, 32, MPI_FORMAT_BIG_ENDIAN);
    }

    if (!error)
    {
        printf("ECDSA signature generated.\r\n");
    }

    // Release previously allocated resources
    ecFreeDomainParameters(&params);
    ecFreePrivateKey(&privateKey);
    ecdsaFreeSignature(&signature);

    // Return status code
    return error;
}

error_t signature_verification()
{
    error_t error;
    EcDomainParameters params;
    EcPublicKey publicKey;
    EcdsaSignature signature;
    uint8_t digest[SHA256_DIGEST_SIZE];

    //Message to be signed
    char_t message[] = "test";

    // ECDSA public key
    uint8_t qx[32] = {
        0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
        0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6};

    uint8_t qy[32] = {
        0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
        0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51, 0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99};

    // ECDSA signature
    uint8_t r[32] = {
        0xF1, 0xAB, 0xB0, 0x23, 0x51, 0x83, 0x51, 0xCD, 0x71, 0xD8, 0x81, 0x56, 0x7B, 0x1E, 0xA6, 0x63,
        0xED, 0x3E, 0xFC, 0xF6, 0xC5, 0x13, 0x2B, 0x35, 0x4F, 0x28, 0xD3, 0xB0, 0xB7, 0xD3, 0x83, 0x67};

    uint8_t s[32] = {
        0x01, 0x9F, 0x41, 0x13, 0x74, 0x2A, 0x2B, 0x14, 0xBD, 0x25, 0x92, 0x6B, 0x49, 0xC6, 0x49, 0x15,
        0x5F, 0x26, 0x7E, 0x60, 0xD3, 0x81, 0x4B, 0x4C, 0x0C, 0xC8, 0x42, 0x50, 0xE4, 0x6F, 0x00, 0x83};

    // Initialize EC domain parameters
    ecInitDomainParameters(&params);
    // Initialize ECDSA public key
    ecInitPublicKey(&publicKey);
    // Initialize ECDSA signature
    ecdsaInitSignature(&signature);

    // Load EC domain parameters
    error = ecLoadDomainParameters(&params, SECP256R1_CURVE);

    // Read ECDSA public key
    if (!error)
    {
        error = mpiImport(&publicKey.q.x, qx, 32, MPI_FORMAT_BIG_ENDIAN);
    }

    if (!error)
    {
        error = mpiImport(&publicKey.q.y, qy, 32, MPI_FORMAT_BIG_ENDIAN);
    }

    // Read ECDSA signature
    if (!error)
    {
        error = mpiImport(&signature.r, r, 32, MPI_FORMAT_BIG_ENDIAN);
    }

    if (!error)
    {
        error = mpiImport(&signature.s, s, 32, MPI_FORMAT_BIG_ENDIAN);
    }

    // Digest the message
    if (!error)
    {
        error = sha256Compute(message, strlen(message), digest);
    }

    // Check status code
    if (!error)
    {
        // Debug message
        printf("verifying ECDSA signature...\r\n");

        // ECDSA signature verification
        error = ecdsaVerifySignature(&params, &publicKey, digest,
                                     SHA256_DIGEST_SIZE, &signature);
    }

    // Check status code
    if (!error)
    {
        // Debug message
        printf("ECDSA signature verified.\r\n");
    }

    // Release previously allocated resources
    ecFreeDomainParameters(&params);
    ecFreePublicKey(&publicKey);
    ecdsaFreeSignature(&signature);

    // Return status code
    return error;
}

int main(int argc, char *argv[])
{
    error_t error;
    uint8_t seed[32];
    size_t length = 32;

    error = init_crypto_rng(seed, length);
    if (error)
    {
        printf("Failed to initialize TRNG seed.\r\n");
    }

    error = signature_generation();
    if (error)
    {
        printf("Failed to generate ECDSA signature.\r\n");
    }

    printf("\r\n");

    error = signature_verification();
    if (error)
    {
        printf("Failed to verify ECDSA signature.\r\n");
    }

    return NO_ERROR;
}
