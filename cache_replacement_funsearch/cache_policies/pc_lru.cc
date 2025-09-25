#include "pc_lru.h"
#include <algorithm>
#include <assert.h>

pc_lru::pc_lru(CACHE* cache) : pc_lru(cache, cache->NUM_SET, cache->NUM_WAY) {}

pc_lru::pc_lru(CACHE* cache, long sets, long ways) : replacement(cache), NUM_WAY(ways) {
    block_metadata.resize(static_cast<std::size_t>(sets * ways), {0, {}, 0});
}

long pc_lru::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set,
                        champsim::address ip, champsim::address full_addr, access_type type)
{
    const auto begin = block_metadata.begin() + (set * NUM_WAY);
    const auto end = begin + NUM_WAY;
    const uint64_t current_pc = ip.pcie();  // Get program counter

    long victim_way = -1;
    uint64_t min_utility = MAX_UTILITY;

    // Find victim based on utility score and PC history
    for (long way = 0; way < NUM_WAY; ++way) {
        auto& meta = begin[way];
        
        // Calculate PC delta from previous accesses
        uint64_t pc_delta = 0;
        if (meta.pc_history[0] != 0) {
            pc_delta = current_pc - meta.pc_history[0];
        }

        // Prefer victims with:
        // 1. Low utility score
        // 2. High PC delta (indicating temporal distance)
        // 3. PC delta above threshold (likely to be non-reused)
        if (meta.utility_score < min_utility ||
            (pc_delta > PC_DELTA_THRESHOLD && meta.utility_score < MAX_UTILITY)) {
            min_utility = meta.utility_score;
            victim_way = way;
        }

        // If we find a block with PC delta above threshold, prefer it as victim
        if (pc_delta > PC_DELTA_THRESHOLD) {
            victim_way = way;
            break;
        }
    }

    // If no victim found with PC delta above threshold, fall back to LRU
    if (victim_way == -1) {
        auto victim = std::min_element(begin, end, [](const CacheBlockMetadata& a, const CacheBlockMetadata& b) {
            return a.last_used_cycle < b.last_used_cycle;
        });
        victim_way = std::distance(begin, victim);
    }

    return victim_way;
}

void pc_lru::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr,
                                    champsim::address ip, champsim::address victim_addr, access_type type)
{
    auto& meta = block_metadata.at(static_cast<std::size_t>(set * NUM_WAY + way));
    meta.last_used_cycle = cycle++;
    meta.pc_history[0] = ip.pcie();  // Store current PC

    // Update utility score based on PC history
    for (int i = 7; i > 0; --i) {
        meta.pc_history[i] = meta.pc_history[i-1];
    }
    
    // Calculate PC delta from previous access
    uint64_t pc_delta = 0;
    if (meta.pc_history[1] != 0) {
        pc_delta = meta.pc_history[0] - meta.pc_history[1];
    }

    // Adjust utility score based on PC delta
    meta.utility_score = std::min(MAX_UTILITY, meta.utility_score + pc_delta / 10);
}

void pc_lru::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr,
                                     champsim::address ip, champsim::address victim_addr, access_type type,
                                     uint8_t hit)
{
    if (hit && access_type{type} != access_type::WRITE) {  // Skip for writeback hits
        auto& meta = block_metadata.at(static_cast<std::size_t>(set * NUM_WAY + way));
        meta.last_used_cycle = cycle++;

        // Update PC history and utility score on hit
        meta.pc_history[0] = ip.pcie();
        for (int i = 7; i > 0; --i) {
            meta.pc_history[i] = meta.pc_history[i-1];
        }

        // Calculate PC delta
        uint64_t pc_delta = 0;
        if (meta.pc_history[1] != 0) {
            pc_delta = meta.pc_history[0] - meta.pc_history[1];
        }

        // Adjust utility score based on PC delta
        meta.utility_score = std::min(MAX_UTILITY, meta.utility_score + pc_delta / 10);
    }
}
