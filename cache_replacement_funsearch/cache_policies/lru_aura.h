#ifndef REPLACEMENT_LRU_AURA_H
#define REPLACEMENT_LRU_AURA_H

#include <vector>
#include <map>
#include "cache.h"
#include "modules.h"

namespace champsim {
    namespace modules {
        namespace replacement {
            
class lru_aura : public champsim::modules::replacement
{
    long NUM_WAY;
    struct block_info {
        uint64_t last_used_cycle;
        uint64_t access_count;
        std::map<uint64_t, uint64_t> pc_access_count;
    };
    
    std::vector[block_info> metadata;
    uint64_t cycle = 0;
    
public:
    explicit lru_aura(CACHE* cache);
    lru_aura(CACHE* cache, long sets, long ways);

    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                    champsim::address full_addr, access_type type);
    void replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                              access_type type);
    void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                                access_type type, uint8_t hit);
};

        } // namespace replacement
    } // namespace modules
} // namespace champsim

#endif
