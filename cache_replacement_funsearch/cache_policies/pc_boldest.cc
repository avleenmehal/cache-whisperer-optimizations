#include "pc_boldest.h"
#include <algorithm>
#include <cassert>
#include <tuple>

pc_boldest::pc_boldest(CACHE* cache) : pc_boldest(cache, cache->NUM_SET, cache->NUM_WAY) {}

pc_boldest::pc_boldest(CACHE* cache, long sets, long ways) : replacement(cache), NUM_WAY(ways), 
  pc_usage(sets, std::vector<uint64_t>(ways, 0)),
  temporal_boldness(sets, std::vector<uint64_t>(ways, 0)),
  spatial_boldness(sets, std::vector<uint64_t>(ways, 0))
{
}

long pc_boldest::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                      champsim::address full_addr, access_type type)
{
  auto pc = ip.get_pc();
  
  // Calculate victim score based on PC usage, temporal boldness, and spatial boldness
  auto begin = std::next(std::begin(pc_usage), set * NUM_WAY);
  auto end = std::next(begin, NUM_WAY);
  
  // Combine metrics to find the least useful block
  auto victim = std::min_element(begin, end, 
    [=](const std::tuple<uint64_t, uint64_t, uint64_t>& a, const std::tuple<uint64_t, uint64_t, uint64_t>& b) {
      return (std::get<0>(a) + std::get<1>(a) + std::get<2>(a)) < 
             (std::get<0>(b) + std::get<1>(b) + std::get<2>(b));
    });
  
  assert(begin <= victim);
  assert(victim < end);
  return std::distance(begin, victim);
}

void pc_boldest::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                 champsim::address victim_addr, access_type type)
{
  auto pc = ip.get_pc();
  pc_usage.at(set * NUM_WAY + way) = cycle++;
}

void pc_boldest::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                   champsim::address victim_addr, access_type type, uint8_t hit)
{
  if (hit && access_type{type} != access_type::WRITE) {
    auto pc = ip.get_pc();
    
    // Update temporal boldness based on recency
    temporal_boldness[set][way] = (cycle - temporal_boldness[set][way] < TEMPORAL_THRESHOLD) ? 
                                temporal_boldness[set][way] + 1 : 0;
    
    // Update spatial boldness based on PC proximity
    spatial_boldness[set][way] = (pc.get_offset() - spatial_boldness[set][way]) < 0x100 ? 
                                spatial_boldness[set][way] + 1 : 0;
    
    // Update PC usage
    pc_usage[set][way] = cycle++;
  }
}
