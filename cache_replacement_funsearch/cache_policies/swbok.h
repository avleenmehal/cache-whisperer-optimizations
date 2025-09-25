#ifndef SWBOK_H
#define SWBOK_H

#include "cache.h"
#include <vector>
#include <queue>

class swbok : public replacement
{
private:
    long NUM_SET;
    long NUM_WAY;
    std::vector<uint64_t> last_used_cycles;  // Track last used cycle for each block
    std::vector<uint64_t> last_used_window;   // Sliding window of recent accesses
    std::vector<uint32_t> frequency;          // Frequency of accesses per block
    uint64_t window_size;                     // Size of the sliding window (e.g., 100 cycles)
    long victim_way;                          // Keep track of victim to reduce thrashing
    uint64_t cycle;                           // Global cycle counter

public:
    swbok(CACHE* cache);
    swbok(CACHE* cache, long sets, long ways);

    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                   champsim::address full_addr, access_type type) override;

    void replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                               access_type type) override;

    void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                 champsim::address victim_addr, access_type type, uint8_t hit) override;
};

#endif  // SWBOK_H
