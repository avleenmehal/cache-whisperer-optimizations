#include "hybrid_adaptive_lru.h"
#include <algorithm>
#include <cassert>

hybrid_adaptive_lru::hybrid_adaptive_lru(CACHE* cache, long sets, long ways, double weight)
    : hybrid_adaptive_lru(cache, sets, ways) {
    this->weight = weight;
}

hybrid_adaptive_lru::hybrid_adaptive_lru(CACHE* cache, double weight)
    : replacement(cache), NUM_WAY(cache->NUM_WAY), weight(weight),
      last_used_cycles(static_cast<std::size_t>(cache->NUM_SET * cache->NUM_WAY), 0),
      frequency(static_cast<std::size_t>(cache->NUM_SET * cache->NUM_WAY), 0),
      pc_histogram(static_cast<std::size_t>(cache->NUM_SET * cache->NUM_WAY), 0),
      utility_score(static_cast<std::size_t>(cache->NUM_SET * cache->NUM_WAY), 0),
      cycle(0) {}

long hybrid_adaptive_lru::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set,
                                     const champsim::cache_block* current_set, champsim::address ip,
                                     champsim::address full_addr, access_type type) {
    const auto begin = std::next(std::begin(last_used_cycles), set * NUM_WAY);
    const auto end = std::next(begin, NUM_WAY);

    // Calculate utility scores and combine with LRU information
    for (auto it = begin; it != end; ++it) {
        const auto index = std::distance(std::begin(last_used_cycles), it);
        const auto recency = cycle - *it;
        const auto inv_recency = static_cast<double>(recency) * 0.1; // Inverse relation
        const auto inv_frequency = static_cast<double>(1.0 / (frequency[index] + 1));
        const auto pc_weight = static_cast<double>(1.0 / (pc_histogram[index] + 1));
        utility_score[index] = static_cast<uint64_t>(inv_recency + inv_frequency + pc_weight);
    }

    // Combine LRU and utility scores with dynamic weighting
    auto begin_utility = std::begin(utility_score) + set * NUM_WAY;
    auto end_utility = begin_utility + NUM_WAY;
    auto begin_lru = begin;

    // Custom comparator that combines LRU and utility scores
    auto victim = std::min_element(begin, end, [begin_utility](const auto& a, const auto& b) {
        const auto index_a = std::distance(std::begin(last_used_cycles), a);
        const auto index_b = std::distance(std::begin(last_used_cycles), b);
        const auto utility_a = *(begin_utility + index_a);
        const auto utility_b = *(begin_utility + index_b);
        // Combine LRU (lower value is better) and utility (lower value is better)
        return ((*a + weight * utility_a) < (*b + weight * utility_b));
    });

    assert(begin <= victim);
    assert(victim < end);
    return std::distance(begin, victim);
}

void hybrid_adaptive_lru::replacement_cache_fill(uint32_t triggering_cpu, long set, long way,
                                                champsim::address full_addr, champsim::address ip,
                                                champsim::address victim_addr, access_type type) {
    const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
    last_used_cycles[index] = cycle++;
    frequency[index]++;
    pc_histogram[index]++;
    utility_score[index] = 0; // Reset utility score
}

void hybrid_adaptive_lru::update_replacement_state(uint32_t triggering_cpu, long set, long way,
                                                   champsim::address full_addr, champsim::address ip,
                                                   champsim::address victim_addr, access_type type,
                                                   uint8_t hit) {
    if (hit && access_type{type} != access_type::WRITE) { // Skip for writeback hits
        const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
        last_used_cycles[index] = cycle++;
        frequency[index]++;
        pc_histogram[index]++;
        utility_score[index] = 0; // Reset utility score
    }
}
