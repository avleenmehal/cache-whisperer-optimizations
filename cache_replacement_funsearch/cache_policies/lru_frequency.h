#ifndef LRU_FREQUENCY_H
#define LRU_FREQUENCY_H

#include "replacement.h"

struct CacheBlockInfo {
    uint64_t last_used;
    uint32_t frequency;
};

class lru_frequency : public replacement {
protected:
    uint64_t cycle;
    std::vector<CacheBlockInfo> last_used_cycles;
    const uint32_t MAX_FREQUENCY;

public:
    lru_frequency(CACHE* cache);
    lru_frequency(CACHE* cache, long sets, long ways);
    ~lru_frequency() {}

    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                    champsim::address full_addr, access_type type) override;

    void replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                               champsim::address victim_addr, access_type type) override;

    void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                 champsim::address victim_addr, access_type type, uint8_t hit) override;
};

#endif // LRU_FREQUENCY_H
