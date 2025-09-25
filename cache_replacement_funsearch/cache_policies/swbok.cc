#include "swbok.h"
#include <algorithm>
#include <cassert>
#include <queue>

swbok::swbok(CACHE* cache) : swbok(cache, cache->NUM_SET, cache->NUM_WAY) {}

swbok::swbok(CACHE* cache, long sets, long ways) : replacement(cache), NUM_SET(sets), NUM_WAY(ways),
                                                   last_used_cycles(sets * ways, 0),
                                                   last_used_window(sets * ways, 0),
                                                   frequency(sets * ways, 0),
                                                   window_size(100),  // Adjustable parameter
                                                   victim_way(-1), cycle(0) {}

long swbok::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                       champsim::address full_addr, access_type type)
{
    const auto begin = std::next(std::begin(last_used_cycles), set * NUM_WAY);
    const auto end = std::next(begin, NUM_WAY);

    // Victim selection using sliding window and frequency
    auto victim = begin;
    uint64_t min_score = std::numeric_limits<uint64_t>::max();

    for (auto it = begin; it != end; ++it)
    {
        const auto index = std::distance(begin, it);
        const auto way = index + set * NUM_WAY;

        // Calculate score: Combine recency and frequency
        uint64_t score = (cycle - *it) + (window_size - last_used_window[way]) + frequency[way] * 2;

        if (score < min_score)
        {
            min_score = score;
            victim = it;
        }
    }

    // Keep track of victim to reduce thrashing
    victim_way = std::distance(begin, victim);
    return victim_way;
}

void swbok::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                                 access_type type)
{
    const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
    last_used_cycles[index] = cycle++;
    last_used_window[index] = cycle % window_size;  // Update sliding window
    frequency[index]++;  // Track access frequency
}

void swbok::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                   champsim::address victim_addr, access_type type, uint8_t hit)
{
    if (hit && type != access_type::WRITE)
    {
        const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
        last_used_cycles[index] = cycle++;
        last_used_window[index] = cycle % window_size;
        frequency[index]++;  // Update frequency on hit
    }

    // If victim is accessed again, promote it
    if (victim_way != -1)
    {
        const auto victim_index = static_cast<std::size_t>(set * NUM_WAY + victim_way);
        if (victim_addr == full_addr)
        {
            last_used_cycles[victim_index] = cycle++;
            last_used_window[victim_index] = cycle % window_size;
            frequency[victim_index]++;  // Update frequency for victim
        }
    }
}
