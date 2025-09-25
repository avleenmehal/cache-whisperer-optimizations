#ifndef HYBRID_ADAPTIVE_LRU_H
#define HYBRID_ADAPTIVE_LRU_H

#include <vector>
#include <cstdint>
#include "replacement.h"

class hybrid_adaptive_lru : public replacement {
private:
    long NUM_WAY;
    std::vector<uint64_t> last_used_cycles;
    std::vector<uint64_t> frequency;
    std::vector<uint64_t> pc_histogram;
    std::vector<uint64_t> utility_score;
    uint64_t cycle;
    double weight;

public:
    hybrid_adaptive_lru(CACHE* cache, long sets = -1, long ways = -1, double weight = 0.5);
    hybrid_adaptive_lru(CACHE* cache, double weight = 0.5);

    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set,
                    champsim::address ip, champsim::address full_addr, access_type type) override;

    void replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr,
                               champsim::address ip, champsim::address victim_addr, access_type type) override;

    void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr,
                                 champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit) override;
};

#endif // HYBRID_ADAPTIVE_LRU_H
