// hybrid_recency_frequency.cc

#include "hybrid_recency_frequency.h"

#include <vector>
#include <algorithm>
#include <cassert>

hybrid_recency_frequency::hybrid_recency_frequency(CACHE* cache) 
    : hybrid_recency_frequency(cache, cache->NUM_SET, cache->NUM_WAY) {}

hybrid_recency_frequency::hybrid_recency_frequency(CACHE* cache, long sets, long ways, double decay)
    : replacement(cache), NUM_WAY(ways), decay_factor(decay),
      last_used_cycles(static_cast<std::size_t>(sets * ways), 0),
      frequency(static_cast<std::size_t>(sets * ways), 0),
      pc_histogram(static_cast<std::size_t>(sets * ways), 0),
      utility_score(static_cast<std::size_t>(sets * ways), 0),
      backup_way(static_cast<std::size_t>(sets), -1) {}

long hybrid_recency_frequency::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set,
                                         const champsim::cache_block* current_set, champsim::address ip,
                                         champsim::address full_addr, access_type type) {
  const auto begin = std::next(std::begin(utility_score), set * NUM_WAY);
  const auto end = std::next(begin, NUM_WAY);

  // Calculate utility scores for each way in the set
  for (auto it = begin; it != end; ++it) {
    const auto index = std::distance(std::begin(utility_score), it);
    const auto recency = cycle - last_used_cycles[index];
    const auto freq = frequency[index];
    const auto pc = pc_histogram[index];
    
    // Calculate utility score combining recency, frequency, and PC histogram
    // Higher recency (older) reduces utility, higher frequency and PC increase utility
    *it = static_cast<uint64_t>((1.0 / recency) + freq + pc);
  }

  const auto victim = std::min_element(begin, end);
  assert(begin <= victim);
  assert(victim < end);
  return std::distance(begin, victim);
}

void hybrid_recency_frequency::replacement_cache_fill(uint32_t triggering_cpu, long set, long way,
                                                       champsim::address full_addr, champsim::address ip,
                                                       champsim::address victim_addr, access_type type) {
  const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
  last_used_cycles[index] = cycle++;
  
  // Apply decay to frequency and PC histogram, then update
  frequency[index] = frequency[index] * decay_factor + 1;
  pc_histogram[index] = pc_histogram[index] * decay_factor + 1;
  utility_score[index] = 0;  // Reset utility score
}

void hybrid_recency_frequency::update_replacement_state(uint32_t triggering_cpu, long set, long way,
                                                        champsim::address full_addr, champsim::address ip,
                                                        champsim::address victim_addr, access_type type,
                                                        uint8_t hit) {
  if (hit && access_type{type} != access_type::WRITE) {  // Skip for writeback hits
    const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
    last_used_cycles[index] = cycle++;
    
    // Apply decay to frequency and PC histogram, then update
    frequency[index] = frequency[index] * decay_factor + 1;
    pc_histogram[index] = pc_histogram[index] * decay_factor + 1;
    utility_score[index] = 0;  // Reset utility score
  }
}
