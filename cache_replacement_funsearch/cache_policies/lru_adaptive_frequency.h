#ifndef __LRU_ADAPTIVE_FREQUENCY_H__
#define __LRU_ADAPTIVE_FREQUENCY_H__

#include "cache.h"
#include <vector>

class lru_adaptive_frequency : public replacement {
private:
    long NUM_WAY;
    std::vector<uint64_t> last_used_cycles;
    std::vector<uint64_t> frequency;
    std::vector<uint64_t> pc_count;
    uint64_t cycle;

public:
    lru_adaptive_frequency(CACHE* cache, long sets, long ways);
    ~lru_adaptive_frequency() {}

    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set,
                    const champsim::cache_block* current_set, champsim::address ip,
                    champsim::address full_addr, access_type type) override;

    void replacement_cache_fill(uint32_t triggering_cpu, long set, long way,
                                champsim::address full_addr, champsim::address ip,
                                champsim::address victim_addr, access_type type) override;

    void update_replacement_state(uint32_t triggering_cpu, long set, long way,
                                    champsim::address full_addr, champsim::address ip,
                                    champsim::address victim_addr, access_type type,
                                    uint8_t hit) override;
};

#endif // __LRU_ADAPTIVE_FREQUENCY_H__
