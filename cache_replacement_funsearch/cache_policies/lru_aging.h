#ifndef __LRU_AGING_H__
#define __LRU_AGING_H__

#include "replacement.h"

class lru_aging : public replacement {
private:
    std::vector<uint64_t> last_used_cycles;
    uint64_t cycle;
    const uint64_t age_interval; // Aging interval in cycles
    const uint64_t age_amount;    // Amount to subtract during aging
    uint64_t last_aging_cycle;

public:
    lru_aging(CACHE* cache, long sets = -1, long ways = -1);
    ~lru_aging();

    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip, champsim::address full_addr, access_type type) override;

    void replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type) override;

    void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit) override;
};

#endif // __LRU_AGING_H__
