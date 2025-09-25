#include "frequent_lru.h"

#include <algorithm>
#include <cassert>

frequent_lru::frequent_lru(CACHE* cache) : frequent_lru(cache, cache->NUM_SET, cache->NUM_WAY) {}

frequent_lru::frequent_lru(CACHE* cache, long sets, long ways)
    : replacement(cache), NUM_SET(sets), NUM_WAY(ways),
      last_used_cycles(static_cast<std::size_t>(sets * ways), 0),
      access_frequency(static_cast<std::size_t>(sets * ways), 0),
      cycle(0) {}

long frequent_lru::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set,
                               const champsim::cache_block* current_set, champsim::address ip,
                               champsim::address full_addr, access_type type) {
    const auto begin = std::next(std::begin(last_used_cycles), set * NUM_WAY);
    const auto end = std::next(begin, NUM_WAY);

    // Find the block with the lowest access frequency
    auto victim = std::min_element(begin, end, [this](const uint64_t& a, const uint64_t& b) {
        return access_frequency[a - begin] < access_frequency[b - begin];
    });

    // Among blocks with the same frequency, choose the one with the oldest last_used_cycle
    if (victim != end) {
        auto first = victim;
        for (++victim; victim != end; ++victim) {
            if (access_frequency[victim - begin] == access_frequency[first - begin] &&
                last_used_cycles[victim - begin] < last_used_cycles[first - begin]) {
                first = victim;
            }
        }
        victim = first;
    }

    return std::distance(begin, victim);
}

void frequent_lru::replacement_cache_fill(uint32_t triggering_cpu, long set, long way,
                                         champsim::address full_addr, champsim::address ip,
                                         champsim::address victim_addr, access_type type) {
    const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
    access_frequency[index]++;
    last_used_cycles[index] = cycle++;
}

void frequent_lru::update_replacement_state(uint32_t triggering_cpu, long set, long way,
                                           champsim::address full_addr, champsim::address ip,
                                           champsim::address victim_addr, access_type type,
                                           uint8_t hit) {
    if (hit && access_type{type} != access_type::WRITE) { // Skip writeback hits
        const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
        access_frequency[index]++;
        last_used_cycles[index] = cycle++;
    }
}
