#ifndef REPLACEMENT_ADAPTIVE_PHOENIX_H
#define REPLACEMENT_ADAPTIVE_PHOENIX_H

#include <vector>
#include "cache.h"
#include "modules.h"

class adaptive_phoenix : public champsim::modules::replacement {
private:
    long NUM_WAY;
    uint64_t cycle = 0;
    
    // Track the last used cycle for each block
    std::vector<uint64_t> last_used_cycles;
    
    // Track the program counter of the last access
    std::vector<uint64_t> pc_history;
    
    // Track the type of accesses (read/write) for pattern detection
    std::vector<uint64_t> access_pattern;
    
    // Track victim blocks that might be bypassed
    std::vector<bool> bypass_candidate;
    
    // Victim cache to track recently evicted blocks
    std::vector<uint64_t> victim_cache;
    
    // Track the number of conflicts for set dueling
    std::vector<uint64_t> set_conflicts;

public:
    explicit adaptive_phoenix(CACHE* cache);
    adaptive_phoenix(CACHE* cache, long sets, long ways);

    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                    champsim::address full_addr, access_type type);
    
    void replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                 champsim::address victim_addr, access_type type);
    
    void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                  champsim::address victim_addr, access_type type, uint8_t hit);

    // Helper function to check if a block should be bypassed
    bool is_write_once(long set, long way) const;
};

#endif
