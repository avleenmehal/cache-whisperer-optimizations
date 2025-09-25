// hybrid_recency_frequency.h

#ifndef HYBRID_REGENCY_FREQUENCY_H
#define HYBRID_REGENCY_FREQUENCY_H

#include "replacement.h"

class hybrid_recency_frequency : public replacement {
private:
    long NUM_WAY;
    std::vector<uint64_t> last_used_cycles;
    std::vector<uint64_t> frequency;
    std::vector<uint64_t> pc_histogram;
    std::vector<uint64_t> utility_score;
    std::vector<int> backup_way;
    const double decay_factor;  // Decay factor for frequency and PC histogram

public:
    hybrid_recency_frequency(CACHE* cache);
    hybrid_recency_frequency(CACHE* cache, long sets, long ways, double decay = 0.95);
    ~hybrid_recency_frequency() {}

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

#endif  // HYBRID_REGENCY_FREQUENCY_H
