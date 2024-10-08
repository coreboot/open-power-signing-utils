/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __STB_CONTAINER_H
#define __STB_CONTAINER_H

#include <stddef.h>
#include <stdint.h>

#include "ccan/endian/endian.h"
#include "ccan/short_types/short_types.h"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

#define PASSED 1
#define FAILED 0
#define UNATTEMPTED -1

#define SECURE_BOOT_HEADERS_SIZE	4096
#define SECURE_BOOT_HEADERS_V2_SIZE	15*1024
#define SECURE_BOOT_HEADERS_V3_SIZE	15*1024
#define SHA256_DIGEST_LENGTH		32

/*
 * The defines and structures below come from the secure ROM source code
 * (trusted_boot_rom). Here you will find only the ones required by the
 * secure and trusted boot implementation in skiboot.
 */

/* From trusted_boot_rom/src/sha512.h */
#define SHA512_DIGEST_LENGTH  64
typedef uint8_t __attribute__((aligned(8))) sha2_hash_t[ SHA512_DIGEST_LENGTH / sizeof(uint8_t) ];
typedef uint8_t sha2_byte; // Exactly 1 byte

/* From trusted_boot_rom/src/hw_utils.h  */
#define ECID_SIZE	16

/* From trusted_boot_rom/src/ecverify.h   */
#define EC_COORDBYTES	66     /* P-521   */
typedef uint8_t ecc_key_t[2*EC_COORDBYTES];
typedef uint8_t ecc_signature_t[2*EC_COORDBYTES];

#define DILITHIUM_PUB_KEY_LENGTH 2336
#define DILITHIUM_SIG_LENGTH 4668

typedef uint8_t dilithium_key_t[DILITHIUM_PUB_KEY_LENGTH];
typedef uint8_t dilithium_signature_t[DILITHIUM_SIG_LENGTH];

#define MLDSA_87_PUB_KEY_LENGTH 2592
#define MLDSA_87_SIG_LENGTH 4627

typedef uint8_t mldsa_key_t[MLDSA_87_PUB_KEY_LENGTH];
typedef uint8_t mldsa_signature_t[MLDSA_87_SIG_LENGTH];

/* From trusted_boot_rom/src/ROM.h */
#define ROM_MAGIC_NUMBER	0x17082011

typedef struct {
	be16 version;		/* (1: see versions above) */
	uint8_t hash_alg;	/* (1: SHA-512 2: SHA3-512) */
	uint8_t sig_alg;	/* (1: SHA-512/ECDSA-521) 2: SHA3-512 ECDSA-521/Dilithium r2 8/7
                                                          3: SHA3-512 ECDSA 521/ML-DSA-87 */
}__attribute__((packed)) ROM_version_raw;

typedef struct {
	ROM_version_raw ver_alg;
	be64 code_start_offset;
	be64 reserved;
	be32 flags;
	uint8_t sw_key_count;
	be64 payload_size;
	sha2_hash_t payload_hash;
	uint8_t ecid_count;
	struct { uint8_t ecid[ECID_SIZE]; } ecid[0]; /* optional ecid place
				    holder ecid_count * ecid_size(128 bits) */
	/* followed by prefix data (sig,keys) key raw */
}__attribute__((packed)) ROM_prefix_header_raw;

typedef struct {
	be32 magic_number;	/* (17082011) */
	be16 version;		/* (1: see versions above) */
	be64 container_size;	/* filled by caller */
	be64 target_hrmor;	/* filled by caller */
	be64 stack_pointer;	/* filled by caller */
	/* bottom of stack -> 128k added by rom code to get real stack pointer */
	ecc_key_t hw_pkey_a;
	ecc_key_t hw_pkey_b;
	ecc_key_t hw_pkey_c;
	/* followed by sw header (if not special prefix) */
	/* followed by optional unprotected payload data */
}__attribute__((packed)) ROM_container_raw;

typedef struct {
	ecc_signature_t hw_sig_a;
	ecc_signature_t hw_sig_b;
	ecc_signature_t hw_sig_c;
	ecc_key_t sw_pkey_p;
	ecc_key_t sw_pkey_q;
	ecc_key_t sw_pkey_r;
}__attribute__((packed)) ROM_prefix_data_raw;

typedef struct {
	ROM_version_raw ver_alg;
	be64 code_start_offset;
	be64 reserved;
	be32 flags;
	uint8_t security_version;
	be64 payload_size;
	sha2_hash_t payload_hash;
	uint8_t ecid_count;
	struct { uint8_t ecid[ECID_SIZE]; } ecid[0]; /* optional ecid place
				    holder ecid_count * ecid_size(128 bits) */
	/* followed by sw sig raw */
}__attribute__((packed)) ROM_sw_header_raw;

typedef struct {
	ecc_signature_t sw_sig_p;
	ecc_signature_t sw_sig_q;
	ecc_signature_t sw_sig_r;
	/* followed by zero's padding to 4K */
	/* followed by protected sw payload_data */
	/* followed by unprotected sw payload_text */
}__attribute__((packed)) ROM_sw_sig_raw;


/* CONTAINER VERSION 2 */
typedef struct {
	ROM_version_raw ver_alg;
	be64 reserved;
	be32 flags;
	uint8_t sw_key_count;
	be64 payload_size;
	sha2_hash_t payload_hash;
	uint8_t ecid[ECID_SIZE];
	uint8_t reserved2[3];
	/* followed by prefix data (sig,keys) key raw */
}__attribute__((packed)) ROM_prefix_header_v2_raw;

typedef struct {
	ecc_signature_t hw_sig_a;
	dilithium_signature_t hw_sig_d;
	ecc_key_t sw_pkey_p;
	dilithium_key_t sw_pkey_s;
}__attribute__((packed)) ROM_prefix_data_v2_raw;

typedef struct {
	ROM_version_raw ver_alg;
	be64 reserved;
	be64 component_id;
	be32 flags;
	uint8_t security_version;
	be64 payload_size;
	be64 unprotected_payload_size;
	sha2_hash_t payload_hash;
	uint8_t ecid[ECID_SIZE];
	uint8_t reserved2[7];
	/* followed by sw sig raw */
}__attribute__((packed)) ROM_sw_header_v2_raw;

typedef struct {
	ecc_signature_t sw_sig_p;
	dilithium_signature_t sw_sig_s;
	/* followed by zero's padding to 15K */
	/* followed by protected sw payload_data */
	/* followed by unprotected sw payload_text */
}__attribute__((packed)) ROM_sw_sig_v2_raw;

typedef struct {
	be32 magic_number;	/* (17082011) */
	be16 version;		/* (2: see versions above) */
	be64 container_size;	/* filled by caller */
	uint8_t reserved[6];
	ecc_key_t hw_pkey_a;
	dilithium_key_t hw_pkey_d;
	ROM_prefix_header_v2_raw prefix;
	ROM_prefix_data_v2_raw   prefix_data;
	ROM_sw_header_v2_raw     swheader;
	ROM_sw_sig_v2_raw        sw_data;
	/* followed by optional unprotected payload data */
}__attribute__((packed)) ROM_container_v2_raw;

/* CONTAINER VERSION 3 */
typedef struct {
	ROM_version_raw ver_alg;
	be64 reserved;
	be32 flags;
	uint8_t sw_key_count;
	be64 payload_size;
	sha2_hash_t payload_hash;
	uint8_t ecid[ECID_SIZE];
	uint8_t reserved2[3];
	/* followed by prefix data (sig,keys) key raw */
}__attribute__((packed)) ROM_prefix_header_v3_raw;

typedef struct {
	ecc_signature_t hw_sig_a;
	mldsa_signature_t hw_sig_d;
	ecc_key_t sw_pkey_p;
	mldsa_key_t sw_pkey_s;
}__attribute__((packed)) ROM_prefix_data_v3_raw;

typedef struct {
	ROM_version_raw ver_alg;
	be64 reserved;
	be64 component_id;
	be32 flags;
	uint8_t security_version;
	be64 payload_size;
	be64 unprotected_payload_size;
	sha2_hash_t payload_hash;
	uint8_t ecid[ECID_SIZE];
	uint8_t reserved2[7];
	/* followed by sw sig raw */
}__attribute__((packed)) ROM_sw_header_v3_raw;

typedef struct {
	ecc_signature_t sw_sig_p;
	mldsa_signature_t sw_sig_s;
	/* followed by zero's padding to 15K */
	/* followed by protected sw payload_data */
	/* followed by unprotected sw payload_text */
}__attribute__((packed)) ROM_sw_sig_v3_raw;

typedef struct {
	be32 magic_number;	/* (17082011) */
	be16 version;		/* (3: see versions above) */
	be64 container_size;	/* filled by caller */
	uint8_t reserved[6];
	ecc_key_t hw_pkey_a;
	mldsa_key_t hw_pkey_d;
	ROM_prefix_header_v3_raw prefix;
	ROM_prefix_data_v3_raw   prefix_data;
	ROM_sw_header_v3_raw     swheader;
	ROM_sw_sig_v3_raw        sw_data;
	/* followed by optional unprotected payload data */
}__attribute__((packed)) ROM_container_v3_raw;


typedef enum { ROM_DONE, ROM_FAILED, PHYP_PARTIAL } ROM_response;

typedef struct {
	sha2_hash_t hw_key_hash;
	uint8_t my_ecid[ECID_SIZE];
	be64 entry_point;
	be64 log;
}__attribute__((packed)) ROM_hw_params;

struct parsed_stb_container {
	const void *buf;
	size_t bufsz;
	const ROM_container_raw *c;
	const ROM_prefix_header_raw *ph;
	const ROM_prefix_data_raw *pd;
	const ROM_sw_header_raw *sh;
	const ROM_sw_sig_raw *ssig;
};

struct parsed_stb_container_v2 {
	const void *buf;
	size_t bufsz;
	const ROM_container_v2_raw *c;
	const ROM_prefix_header_v2_raw *ph;
	const ROM_prefix_data_v2_raw *pd;
	const ROM_sw_header_v2_raw *sh;
	const ROM_sw_sig_v2_raw *ssig;
};

struct parsed_stb_container_v3 {
	const void *buf;
	size_t bufsz;
	const ROM_container_v3_raw *c;
	const ROM_prefix_header_v3_raw *ph;
	const ROM_prefix_data_v3_raw *pd;
	const ROM_sw_header_v3_raw *sh;
	const ROM_sw_sig_v3_raw *ssig;
};

#endif /* __STB_CONTAINER_H */
