add_library(cyclone_crypto "")

target_include_directories(cyclone_crypto
        PUBLIC
        ${PROJECT_SOURCE_DIR}/lib/
        ${PROJECT_SOURCE_DIR}/lib/common
        ${PROJECT_SOURCE_DIR}/lib/core

        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/)

# add the main library
# add VxWorks specific port file here, instead of Linux
if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    target_sources(cyclone_crypto
            PUBLIC
            ${PROJECT_SOURCE_DIR}/lib/common/os_port_posix.h # modified from os_port_posix.h
            ${PROJECT_SOURCE_DIR}/lib/common/os_port_posix.c # modified from os_port_posix.c
            )
endif()
if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    target_sources(cyclone_crypto
            PUBLIC
            ${PROJECT_SOURCE_DIR}/lib/common/os_port_windows.h
            ${PROJECT_SOURCE_DIR}/lib/common/os_port_windows.c
            )
endif()
target_sources(cyclone_crypto
        PUBLIC
        ${PROJECT_SOURCE_DIR}/lib/os_port_config.h
        ${PROJECT_SOURCE_DIR}/lib/crypto_config.h
        ${PROJECT_SOURCE_DIR}/lib/common/os_port.h
        ${PROJECT_SOURCE_DIR}/lib/common/cpu_endian.c
        ${PROJECT_SOURCE_DIR}/lib/common/cpu_endian.h
        ${PROJECT_SOURCE_DIR}/lib/common/date_time.c
        ${PROJECT_SOURCE_DIR}/lib/common/date_time.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/hash/sha512.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/hash/sha512.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/hash/sha256.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/hash/sha256.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/hash/sha384.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/hash/sha384.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/hash/sha1.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/hash/sha1.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/rng/yarrow.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/rng/yarrow.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/cipher/aes.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/cipher/aes.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkc/rsa.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkc/rsa.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkc/dsa.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkc/dsa.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/encoding/oid.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/encoding/oid.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/encoding/asn1.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/encoding/asn1.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/encoding/base64.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/encoding/base64.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/mpi/mpi.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/mpi/mpi.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_common.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_common.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/ecc/ec_curves.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/ecc/ec_curves.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/ecc/curve25519.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/ecc/curve25519.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/ecc/ecdsa.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/ecc/ecdsa.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/ecc/ec.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/ecc/ec.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkc/rsa.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkc/rsa.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/pem_common.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/pem_common.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/pem_decrypt.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/pem_decrypt.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/pem_import.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/pem_import.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_sign_generate.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_sign_generate.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_sign_format.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_sign_format.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_sign_parse.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_sign_parse.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_sign_verify.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_sign_verify.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_create.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_create.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_parse.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_parse.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_ext_parse.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_ext_parse.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_ext_format.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_ext_format.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_validate.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_validate.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_format.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_cert_format.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_key_parse.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_key_parse.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_key_format.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/x509_key_format.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/pkcs8_key_format.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/pkcs8_key_format.h
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/pkcs8_key_parse.c
        ${PROJECT_SOURCE_DIR}/lib/cyclone_crypto/pkix/pkcs8_key_parse.h
)