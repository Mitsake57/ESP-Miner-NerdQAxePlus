#include <string.h>
#include "esp_timer.h" // new

#include "esp_log.h"

#include "serial.h"
#include "utils.h"
#include "global_state.h"
#include "nvs_config.h"
#include "system.h"
#include "boards/board.h"

#include "simple_ring64.hpp"
#include "utils.h"

static const char *TAG = "asic_result";

static SimpleRing64<32> s_seen_keys;

static uint64_t duplicateHWNonces = 0;

static void countDuplicateHWNonces() {
    duplicateHWNonces++;
}

uint64_t getDuplicateHWNonces() {
    return duplicateHWNonces;
}

// Combine nonce + version into a single 64-bit key
static inline uint64_t make_key(uint32_t nonce, uint32_t version)
{
    // This order must be consistent everywhere
    return (uint64_t(nonce) << 32) | uint64_t(version);
}

void ASIC_result_task(void *pvParameters)
{
    static uint64_t profile_count = 0;      // new
    static int64_t last_result_us = 0;      // new

    static uint64_t total_gap_us = 0;       // new
    static uint64_t total_verify_us = 0;    // new
    static uint64_t total_submit_us = 0;    // new


    Board* board = SYSTEM_MODULE.getBoard();
    Asic* asics = board->getAsics();

    while (1) {
        if (POWER_MANAGEMENT_MODULE.isShutdown()) {
            ESP_LOGW(TAG, "suspended");
            vTaskSuspend(NULL);
        }
        //ESP_LOGI("Memory", "%lu", esp_get_free_heap_size()); test
        task_result asic_result;

        // get the result
        if (!asics->processWork(&asic_result)) {
            continue;
        }

        if (asic_result.is_reg_resp) {
            switch (asic_result.reg) {
                case 0xb4: {
                    if (asic_result.data & 0x80000000) {
                        float ftemp = (float) (asic_result.data & 0x0000ffff) * 0.171342f - 299.5144f;
                        ESP_LOGI(TAG, "asic %d temp: %.3f", (int) asic_result.asic_nr, ftemp);
                        board->setChipTemp(asic_result.asic_nr, ftemp);
                    }
                    break;
                }
                case 0x48: {
                    // maybe the upper 32bit of a 64bit counter and 0x90 returns the lower 32bit
                    break;
                }
                case 0x90: {
                    HASHRATE_MONITOR.onRegisterReply(asic_result.asic_nr, asic_result.data);
                    break;
                }
                default: {
                    // NOP
                    break;
                }
            }
            continue;
        }

        uint8_t asic_job_id = asic_result.job_id;

        bm_job *job = asicJobs.getClone(asic_job_id);
        if (!job) {
            //ESP_LOGI(TAG, "Invalid job id found, 0x%02X", asic_job_id);
            continue;
        }

        static uint64_t result_count = 0; // new
        static uint64_t gap_count = 0; // new

        int64_t result_us = esp_timer_get_time(); // new

        if (last_result_us != 0) { // new
            total_gap_us += result_us - last_result_us;
            gap_count++;
        }

        last_result_us = result_us; // new
        result_count++; // new

        // now we have the original job and can `or` the version
        asic_result.rolled_version |= job->version;

        
        int64_t verify_start = esp_timer_get_time(); // new

        // check the nonce difficulty
        double nonce_diff =
            test_nonce_value(job, asic_result.nonce, asic_result.rolled_version);

        total_verify_us += esp_timer_get_time() - verify_start; // new

        // get best known session diff
        char bestDiffString[16];
        suffixString(STRATUM_MANAGER->getBestSessionDiff(), bestDiffString, sizeof(bestDiffString), 3);

        const char *pool_str = job->pool_id ? "Sec" : "Pri";

        // log the ASIC response, including pool and best session difficulty using human-readable SI formatting
        // we only show responses >= maxAsicDifficulty to avoid spamming the log
        // change for dual pool because the pool with lower % can reduce asic HW difficulty
        if (nonce_diff >= board->getAsicMaxDifficulty()) { // new
            ESP_LOGI(TAG, "(%s) Job ID: %02X AsicNr: %d Ver: %08" PRIX32 " Nonce %08" PRIX32 "; Extranonce2 %s diff %.1f/%lu/%s",
                pool_str, asic_job_id, asic_result.asic_nr, asic_result.rolled_version, asic_result.nonce, job->extranonce2,
                nonce_diff, job->pool_diff, bestDiffString);
        }

        uint64_t key = make_key(asic_result.nonce, asic_result.rolled_version);
        bool duplicate = !s_seen_keys.insert_if_absent(key);
        if (duplicate) {
            ESP_LOGW(TAG, "(%s) duplicate share detected!", pool_str);
            countDuplicateHWNonces();
        }

        if (!duplicate && nonce_diff >= board->getAsicMaxDifficulty()) {
            SYSTEM_MODULE.pushShare(asic_result.asic_nr);
        }

        // send duplicates to the server (they will get rejected and counted as rejected)
        if (nonce_diff >= job->pool_diff) { 
            int64_t submit_start = esp_timer_get_time(); // new

            STRATUM_MANAGER->submitShare(
                job->pool_id,
                job->jobid,
                job->extranonce2,
                job->ntime,
                asic_result.nonce,
                asic_result.rolled_version,
                job->version
            );

            total_submit_us += esp_timer_get_time() - submit_start; // new

            profile_count++; // new

            if (profile_count % 1000 == 0) {
                ESP_LOGI(
                    TAG,
                    "PROFILE: avg ASIC result gap=%llu us, verify=%llu us, submit=%llu us",
                    gap_count ? total_gap_us / gap_count : 0,
                    result_count ? total_verify_us / result_count : 0,
                    profile_count ? total_submit_us / profile_count : 0
                );
            }
        }

        STRATUM_MANAGER->checkForBestDiff(job->pool_id, nonce_diff, job->target);

        STRATUM_MANAGER->checkForFoundBlock(job->pool_id, nonce_diff, job->target);


        free_bm_job(job);
    }
}
