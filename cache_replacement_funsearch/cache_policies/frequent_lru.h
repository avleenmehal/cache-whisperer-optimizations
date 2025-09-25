#ifndef FREQUENT_LRU_H
#define FREQUENT_LRU_H

#include "replacement.h"

class frequent_lru : public replacement {
protected:
    long NUM_SET;
    long NUM_WAY;
    std::vector<uint64_t> last_used_cycles;
    std::vector<uint32_t> access_frequency;
    uint64_t cycle;

public:
    frequent_lru(CACHE* cache);
    frequent_lru(CACHE* cache, long sets, long ways);

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

#endif // FREQUENT_LRU_H
