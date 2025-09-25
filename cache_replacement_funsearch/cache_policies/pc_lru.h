#ifndef REPLACEMENT_PC_LRU_H
#define REPLACEMENT_PC_LRU_H

#include <vector>
#include "cache.h"
#include "modules.h"

struct CacheBlockMetadata {
    uint64_t last_used_cycle;
    uint64_t pc_history[8];  // Track last 8 PCs accessing this block
    uint64_t utility_score;    // Dynamic utility score based on access patterns
};

class pc_lru : public champsim::modules::replacement {
protected:
    long NUM_WAY;
    std::vector<CacheBlockMetadata> block_metadata;
    uint64_t cycle = 0;
    const uint64_t PC_DELTA_THRESHOLD = 1000;  // Threshold for PC-based prediction
    const uint64_t MAX_UTILITY = 10000;         // Maximum utility score

public:
    explicit pc_lru(CACHE* cache);
    pc_lru(CACHE* cache, long sets, long ways);

    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                    champsim::address full_addr, access_type type) override;
    void replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                               champsim::address victim_addr, access_type type) override;
    void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                 champsim::address victim_addr, access_type type, uint8_t hit) override;
};

#endif
