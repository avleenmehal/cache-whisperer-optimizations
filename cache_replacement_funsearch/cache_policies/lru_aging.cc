#include "lru_aging.h"

#include <algorithm>
#include <cassert>

lru_aging::lru_aging(CACHE* cache, long sets, long ways) : replacement(cache), cycle(0), age_interval(1000), age_amount(1000), last_aging_cycle(0) {
    if (sets == -1)
        sets = cache->NUM_SET;
    if (ways == -1)
        ways = cache->NUM_WAY;
    last_used_cycles.resize(sets * ways, 0);
}

lru_aging::~lru_aging() {}

long lru_aging::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip, champsim::address full_addr, access_type type) {
    const auto begin = std::next(last_used_cycles.begin(), set * NUM_WAY);
    const auto end = std::next(begin, NUM_WAY);

    // Check if it's time to age the last_used_cycles
    if (cycle - last_aging_cycle >= age_interval) {
        for (auto it = last_used_cycles.begin(); it != last_used_cycles.end(); ++it) {
            if (*it > age_amount)
                *it -= age_amount;
            else
                *it = 0;
        }
        last_aging_cycle = cycle;
    }

    const auto victim = std::min_element(begin, end);
    assert(begin <= victim);
    assert(victim < end);
    return std::distance(begin, victim);
}

void lru_aging::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type) {
    last_used_cycles.at(static_cast<std::size_t>(set * NUM_WAY + way)) = cycle++;
}

void lru_aging::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit) {
    if (hit && type != access_type::WRITE) {
        last_used_cycles.at(static_cast<std::size_t>(set * NUM_WAY + way)) = cycle++;
    }
}
