#include "lru_frequency.h"

#include <algorithm>
#include <cassert>

lru_frequency::lru_frequency(CACHE* cache) : lru_frequency(cache, cache->NUM_SET, cache->NUM_WAY) {}

lru_frequency::lru_frequency(CACHE* cache, long sets, long ways) : replacement(cache), last_used_cycles(static_cast<std::size_t>(sets * ways)), MAX_FREQUENCY(1000) {
    cycle = 0;
    for (auto& info : last_used_cycles) {
        info.last_used = 0;
        info.frequency = 0;
    }
}

long lru_frequency::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                              champsim::address full_addr, access_type type)
{
    const auto set_start = set * NUM_WAY;
    const auto set_end = set_start + NUM_WAY;
    size_t victim_way = 0;
    uint64_t max_score = 0;

    for (size_t way = set_start; way < set_end; ++way) {
        const auto& info = last_used_cycles[way];
        const uint64_t time_since = cycle - info.last_used;
        const uint32_t frequency = MAX_FREQUENCY - info.frequency;
        const uint64_t score = time_since + frequency;

        if (score > max_score) {
            max_score = score;
            victim_way = way;
        }
    }

    return victim_way - set_start;
}

void lru_frequency::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                  champsim::address victim_addr, access_type type)
{
    const size_t way_idx = static_cast<size_t>(set * NUM_WAY + way);
    last_used_cycles[way_idx].last_used = cycle++;
    last_used_cycles[way_idx].frequency = 1; // Reset frequency when filled
}

void lru_frequency::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                   champsim::address victim_addr, access_type type, uint8_t hit)
{
    if (hit && access_type{type} != access_type::WRITE) { // Skip for writeback hits
        const size_t way_idx = static_cast<size_t>(set * NUM_WAY + way);
        last_used_cycles[way_idx].last_used = cycle++;
        last_used_cycles[way_idx].frequency++;
    }
}
