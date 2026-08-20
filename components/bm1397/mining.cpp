#include "mining.h"
#include "mbedtls/sha256.h"
#include "mining_utils.h"
#include "macros.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "esp_log.h"

static const char *TAG = "MINING";

void free_bm_job(bm_job *job)
{
    free(job->jobid);
    free(job->extranonce2);
    free(job);
}

void calculate_merkle_root_hash(const char *coinbase_tx, const uint8_t merkle_branches[][32], const int num_merkle_branches,
                                char merkle_root_hash[65])
{
    size_t coinbase_tx_bin_len = strlen(coinbase_tx) / 2;
    uint8_t *coinbase_tx_bin = (uint8_t *) MALLOC(coinbase_tx_bin_len);

    hex2bin(coinbase_tx, coinbase_tx_bin, coinbase_tx_bin_len);

    uint8_t both_merkles[64];
    uint8_t new_root[32];
    double_sha256_bin(coinbase_tx_bin, coinbase_tx_bin_len, new_root);
    free(coinbase_tx_bin);

    memcpy(both_merkles, new_root, 32);
    for (int i = 0; i < num_merkle_branches; i++) {
        memcpy(both_merkles + 32, merkle_branches[i], 32);
        double_sha256_bin(both_merkles, 64, new_root);
        memcpy(both_merkles, new_root, 32);
    }

    bin2hex(both_merkles, 32, merkle_root_hash, 65);
}

// Normal Stratum V1 path.
// Take a mining_notify struct plus the calculated Merkle root and convert it
// into the representation expected by bm_job / the ASIC packet.
void construct_bm_job(mining_notify *params, const char *merkle_root, const uint32_t version_mask, bm_job *new_job)
{
    new_job->version = params->version;
    new_job->version_mask = version_mask;
    new_job->starting_nonce = 0;
    new_job->target = params->target;
    new_job->ntime = params->ntime;
    new_job->pool_diff = params->difficulty;

    // Logical header representation used by test_nonce_value().
    hex2bin(merkle_root, new_job->merkle_root, 32);

    // Representation expected by the ASIC packet.
    swap_endian_words(merkle_root, new_job->merkle_root_be);
    reverse_bytes(new_job->merkle_root_be, 32);

    // Logical header representation used by test_nonce_value().
    swap_endian_words_bin(params->_prev_block_hash, new_job->prev_block_hash, HASH_SIZE);

    // Representation expected by the ASIC packet.
    memcpy(new_job->prev_block_hash_be, params->_prev_block_hash, HASH_SIZE);
    reverse_bytes(new_job->prev_block_hash_be, HASH_SIZE);
}

// Raw-header path.
// params->raw_header contains exactly the first 76 serialized header bytes:
//   [0..3]   version
//   [4..35]  previous-block field
//   [36..67] arbitrary 32-byte field (normally Merkle root)
//   [68..71] nTime
//   [72..75] nBits
// The nonce is not supplied; the ASIC searches it.
//
// Nothing in this function derives or hashes any of those 76 bytes. The only
// transformation is the representation conversion required by the ASIC packet
// for the two 32-byte fields.
void construct_raw_bm_job(mining_notify *params, const uint32_t version_mask, bm_job *new_job)
{
    const uint8_t *header = params->raw_header;

    // Preserve the exact serialized bytes in the logical bm_job fields.
    // ESP32-S3 is little-endian, so memcpy into these uint32_t fields makes a
    // later memcpy back to an 80-byte header reproduce the original bytes.
    memcpy(&new_job->version, header, 4);
    memcpy(new_job->prev_block_hash, header + 4, 32);
    memcpy(new_job->merkle_root, header + 36, 32);
    memcpy(&new_job->ntime, header + 68, 4);
    memcpy(&new_job->target, header + 72, 4);

    new_job->version_mask = version_mask;
    new_job->starting_nonce = 0;
    new_job->pool_diff = params->difficulty;

    // Convert each 32-byte logical header field to the ordering expected by
    // the BM1370/BM1368 job packet. This reverses the order of 32-bit words
    // while preserving the byte order inside each word.
    swap_endian_words_bin(new_job->prev_block_hash, new_job->prev_block_hash_be, HASH_SIZE);
    reverse_bytes(new_job->prev_block_hash_be, HASH_SIZE);

    swap_endian_words_bin(new_job->merkle_root, new_job->merkle_root_be, HASH_SIZE);
    reverse_bytes(new_job->merkle_root_be, HASH_SIZE);

    ESP_LOGI(TAG, "USING RAW 76-BYTE HEADER JOB");
    ESP_LOG_BUFFER_HEX(TAG, params->raw_header, RAW_HEADER_SIZE);
}

/////// cgminer nonce testing
/* truediffone == 0x00000000FFFF0000000000000000000000000000000000000000000000000000 */
static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;

/* testing a nonce and return the diff - 0 means invalid */
double test_nonce_value(const bm_job *job, const uint32_t nonce, const uint32_t rolled_version)
{
    double d64, s64, ds;
    unsigned char header[80];

    // Reconstruct the exact 80-byte header hashed by the host:
    // rolled version + the preserved 72 bytes + ASIC-reported nonce.
    memcpy(header, &rolled_version, 4);
    memcpy(header + 4, job->prev_block_hash, 32);
    memcpy(header + 36, job->merkle_root, 32);
    memcpy(header + 68, &job->ntime, 4);
    memcpy(header + 72, &job->target, 4);
    memcpy(header + 76, &nonce, 4);

    unsigned char hash_buffer[32];
    unsigned char hash_result[32];

    // double hash the header
    mbedtls_sha256(header, 80, hash_buffer, 0);
    mbedtls_sha256(hash_buffer, 32, hash_result, 0);

    d64 = truediffone;
    s64 = le256todouble(hash_result);
    ds = d64 / s64;

    return ds;
}
