#include "frec.h"
#include <algorithm>
#include <cassert>

frec::frec(CACHE* cache) : frec(cache, cache->NUM_SET, cache->NUM_WAY) {}

frec::frec(CACHE* cache, long sets, long ways) : replacement(cache), NUM_SET(sets), NUM_WAY(ways), 
                                                last_used_cycles(static_cast<std::size_t>(sets * ways), 0),
                                                access_frequency(static_cast<std::size_t>(sets * ways), 0),
                                                cycle(0)
{
}

long frec::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set,
                      champsim::address ip, champsim::address full_addr, access_type type)
{
    const auto begin = std::next(std::begin(last_used_cycles), set * NUM_WAY);
    const auto end = std::next(begin, NUM_WAY);
    
    // Find the block with the lowest access frequency (cold block)
    auto begin_freq = std::next(std::begin(access_frequency), set * NUM_WAY);
    auto end_freq = std::next(begin_freq, NUM_WAY);
    
    auto victim = std::min_element(begin_freq, end_freq, [](uint64_t a, uint64_t b) {
        return a < b;
    });
    
    // If multiple blocks have the same frequency, fall back to LRU
    if (std::distance(begin_freq, std::find(end_freq, *begin_freq, *begin_freq)) > 1) {
        auto victim_lru = std::min_element(begin, end);
        return std::distance(begin, victim_lru);
    }
    
    return std::distance(begin, victim);
}

void frec::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr,
                                 champsim::address ip, champsim::address victim_addr, access_type type)
{
    access_frequency.at((std::size_t)(set * NUM_WAY + way))++;
    last_used_cycles.at((std::size_t)(set * NUM_WAY + way)) = cycle++;
}

void frec::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr,
                                   champsim::address ip, champsim::address victim_addr, access_type type,
                                   uint8_t hit)
{
    if (hit && access_type{type} != access_type::WRITE) {
        access_frequency.at((std::size_t)(set * NUM_WAY + way))++;
        last_used_cycles.at((std::size_t)(set * NUM_WAY + way)) = cycle++;
    }
}
