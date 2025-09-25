#include "adaptive_reuse.h"

#include <vector>
#include <algorithm>
#include <cassert>

adaptive_reuse::adaptive_reuse(CACHE* cache) : adaptive_reuse(cache, cache->NUM_SET, cache->NUM_WAY) {}

adaptive_reuse::adaptive_reuse(CACHE* cache, long sets, long ways) : replacement(cache), NUM_WAY(ways),
  last_used_cycles(static_cast<std::size_t>(sets * ways), 0),
  frequency(static_cast<std::size_t>(sets * ways), 0),
  pc_histogram(static_cast<std::size_t>(sets * ways), 0),
  utility_score(static_cast<std::size_t>(sets * ways), 0),
  backup_way(static_cast<std::size_t>(sets), -1) {}

long adaptive_reuse::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set,
                                champsim::address ip, champsim::address full_addr, access_type type) {
  const auto begin = std::next(std::begin(utility_score), set * NUM_WAY);
  const auto end = std::next(begin, NUM_WAY);

  // Calculate utility scores for each way in the set
  for (auto it = begin; it != end; ++it) {
    const auto index = std::distance(std::begin(utility_score), it);
    const auto recency = cycle - last_used_cycles[index];
    const auto inv_recency = static_cast<double>(recency) * 0.1; // Inverse relation
    const auto inv_frequency = static_cast<double>(1.0 / (frequency[index] + 1));
    const auto pc_weight = static_cast<double>(1.0 / (pc_histogram[index] + 1));
    *it = static_cast<uint64_t>(inv_recency + inv_frequency + pc_weight);
  }

  const auto victim = std::min_element(begin, end);
  assert(begin <= victim);
  assert(victim < end);
  return std::distance(begin, victim);
}

void adaptive_reuse::replacement_cache_fill(uint32_t triggering_cpu, long set, long way,
                                            champsim::address full_addr, champsim::address ip,
                                            champsim::address victim_addr, access_type type) {
  const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
  last_used_cycles[index] = cycle++;
  frequency[index]++;
  pc_histogram[index]++;
  utility_score[index] = 0; // Reset utility score
}

void adaptive_reuse::update_replacement_state(uint32_t triggering_cpu, long set, long way,
                                             champsim::address full_addr, champsim::address ip,
                                             champsim::address victim_addr, access_type type, uint8_t hit) {
  if (hit && access_type{type} != access_type::WRITE) { // Skip for writeback hits
    const auto index = static_cast<std::size_t>(set * NUM_WAY + way);
    last_used_cycles[index] = cycle++;
    frequency[index]++;
    pc_histogram[index]++;
    utility_score[index] = 0; // Reset utility score
  }
}
