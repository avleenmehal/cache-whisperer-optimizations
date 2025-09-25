#include "hybridreuse.h"

#include <vector>
#include <algorithm>
#include <cassert>

hybridreuse::hybridreuse(CACHE* cache) : hybridreuse(cache, cache->NUM_SET, cache->NUM_WAY) {}

hybridreuse::hybridreuse(CACHE* cache, long sets, long ways) : 
    replacement(cache), 
    NUM_WAY(ways),
    last_used_cycles(static_cast<std::size_t>(sets * ways), 0),
    frequency(static_cast<std::size_t>(sets * ways), 0),
    pc_histogram(static_cast<std::size_t>(sets * ways), 0),
    utility_score(static_cast<std::size_t>(sets * ways), 0),
    backup_way(static_cast<std::size_t>(sets), -1),
    cycle(0),
    temperature(1000.0) {
        // High initial temperature for exploration
    }

long hybridreuse::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, 
                              const champsim::cache_block* current_set, champsim::address ip,
                              champsim::address full_addr, access_type type) {
    const auto begin = std::next(std::begin(utility_score), set * NUM_WAY);
    const auto end = std::next(begin, NUM_WAY);

    // Calculate utility scores with temperature-based weights
    for (auto it = begin; it != end; ++it) {
        const auto index = std::distance(std::begin(utility_score), it);
        const auto recency = static_cast<double>(cycle - last_used_cycles[index]);
        const auto inv_recency = recency * 0.1; // Inverse relation
        
        const auto freq_weight = static_cast<double>(1.0 / (frequency[index] + 1));
        const auto pc_weight = static_cast<double>(1.0 / (pc_histogram[index] + 1));
        
        // Temperature-based weight adjustment
        const auto temperature_weight = std::exp(-recency / temperature);
        
        // Combined utility score
        *it = static_cast<uint64_t>(inv_recency * temperature_weight + 
                                   freq_weight * (1 - temperature_weight) + 
                                   pc_weight * (1 - temperature_weight));
    }

    const auto victim = std::min_element(begin, end);
    assert(begin <= victim);
    assert(victim < end);
    return std::distance(begin, victim);
}

void hybridreuse::replacement_cache_fill(uint32_t triggering_cpu, long set, long way,
                                        champsim::address full_addr, champsim::address ip,
                                        champsim::address victim_addr, access_type type) {
    const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
    last_used_cycles[index] = cycle++;
    frequency[index]++;
    pc_histogram[index]++;
    utility_score[index] = 0; // Reset utility score
    
    // Gradually decrease temperature for exploitation
    temperature *= 0.9999;
}

void hybridreuse::update_replacement_state(uint32_t triggering_cpu, long set, long way,
                                         champsim::address full_addr, champsim::address ip,
                                         champsim::address victim_addr, access_type type, uint8_t hit) {
    if (hit && access_type{type} != access_type::WRITE) { // Skip for writeback hits
        const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
        last_used_cycles[index] = cycle++;
        frequency[index]++;
        pc_histogram[index]++;
        utility_score[index] = 0; // Reset utility score
        
        // Gradually decrease temperature for exploitation
        temperature *= 0.9999;
    }
}
