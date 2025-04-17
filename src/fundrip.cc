
#include "fundrip.h"

#include <algorithm>
#include <cassert>
#include <random>
#include <utility>
#include <cmath>
#include <bitset>

#include "champsim.h"

fundrip::fundrip(CACHE* cache) : 
  replacement(cache), 
  NUM_SET(cache->NUM_SET), 
  NUM_WAY(cache->NUM_WAY), 
  rrpv(static_cast<std::size_t>(NUM_SET * NUM_WAY)),
  signature(static_cast<std::size_t>(NUM_SET * NUM_WAY), 0),
  outcome(static_cast<std::size_t>(NUM_SET * NUM_WAY), 0),
  last_access_time(static_cast<std::size_t>(NUM_SET * NUM_WAY), 0),
  access_count(static_cast<std::size_t>(NUM_SET * NUM_WAY), 0),
  pc_table(1 << SIGNATURE_SIZE, maxRRPV / 2),
  signature_table(1 << SIGNATURE_SIZE, maxRRPV / 2),
  burst_table(1 << SIGNATURE_SIZE, 0),
  current_time(0),
  bip_counter(0),
  program_phase(0)
{
  // Randomly selected sampler sets with improved distribution
  std::size_t TOTAL_SDM_SETS = NUM_CPUS * NUM_POLICY * SDM_SIZE;
  
  // Use improved random number generation for better set distribution
  std::mt19937 gen(42); // Fixed seed for reproducibility
  std::uniform_int_distribution<long> dist(0, NUM_SET - 1);
  
  // Generate random sets, ensuring no duplicates
  std::set<long> unique_sets;
  while (unique_sets.size() < TOTAL_SDM_SETS) {
    unique_sets.insert(dist(gen));
  }
  
  rand_sets.assign(unique_sets.begin(), unique_sets.end());
  std::sort(std::begin(rand_sets), std::end(rand_sets));
  
  // Initialize policy selectors with slight bias toward SRRIP (often better default)
  std::fill_n(std::back_inserter(PSEL), NUM_CPUS, typename decltype(PSEL)::value_type{5});
}

unsigned& fundrip::get_rrpv(long set, long way) 
{ 
  return rrpv.at(static_cast<std::size_t>(set * NUM_WAY + way)); 
}

uint64_t& fundrip::get_signature(long set, long way) 
{ 
  return signature.at(static_cast<std::size_t>(set * NUM_WAY + way)); 
}

uint8_t& fundrip::get_outcome(long set, long way) 
{ 
  return outcome.at(static_cast<std::size_t>(set * NUM_WAY + way)); 
}

uint64_t& fundrip::get_last_access_time(long set, long way) 
{ 
  return last_access_time.at(static_cast<std::size_t>(set * NUM_WAY + way)); 
}

uint8_t& fundrip::get_access_count(long set, long way) 
{ 
  return access_count.at(static_cast<std::size_t>(set * NUM_WAY + way)); 
}

uint64_t fundrip::hash_pc(champsim::address pc)
{
  // FNV-1a hash for better distribution of PC values
  constexpr uint64_t FNV_PRIME = 1099511628211ULL;
  constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
  
  uint64_t hash = FNV_OFFSET;
  
  for (int i = 0; i < 8; i++) {
    uint8_t byte = static_cast<uint8_t>((pc >> (i * 8)) & 0xFF);
    hash ^= byte;
    hash *= FNV_PRIME;
  }
  
  return hash & ((1 << SIGNATURE_SIZE) - 1); // Mask to signature size
}

uint64_t fundrip::update_signature(uint64_t old_sig, champsim::address pc)
{
  uint64_t pc_hash = hash_pc(pc);
  
  // Signature update with folding to reduce aliasing
  uint64_t new_sig = ((old_sig << 3) ^ (old_sig >> (SIGNATURE_SIZE - 3)) ^ pc_hash) & 
                     ((1 << SIGNATURE_SIZE) - 1);
  
  return new_sig;
}

void fundrip::update_pc_table(champsim::address pc, bool hit)
{
  uint64_t pc_index = hash_pc(pc);
  
  // Saturating counter update with stronger update on hits
  if (hit) {
    if (pc_table[pc_index] > 0)
      pc_table[pc_index]--;
  } else {
    if (pc_table[pc_index] < (1 << COUNTER_BITS) - 1)
      pc_table[pc_index]++;
  }
}

void fundrip::update_signature_table(uint64_t sig, bool hit)
{
  // Signature-based prediction with asymmetric learning rates
  if (hit) {
    if (signature_table[sig] > 0)
      signature_table[sig] = std::max(0, static_cast<int>(signature_table[sig]) - 2);
  } else {
    if (signature_table[sig] < (1 << COUNTER_BITS) - 1)
      signature_table[sig]++;
  }
}

void fundrip::detect_program_phase()
{
  // Simple phase detection based on access patterns
  if (recent_accesses.size() < ACCESS_HISTORY_SIZE)
    return;
    
  // Count unique addresses in recent history
  std::unordered_set<champsim::address> unique_addrs;
  for (auto addr : recent_accesses) {
    unique_addrs.insert(addr);
  }
  
  // Calculate locality score
  float locality = static_cast<float>(unique_addrs.size()) / recent_accesses.size();
  
  // Update phase based on locality
  if (locality < 0.2) {
    program_phase = 0; // High locality phase
  } else if (locality < 0.5) {
    program_phase = 1; // Medium locality phase
  } else {
    program_phase = 2; // Low locality phase
  }
}

void fundrip::update_bip(long set, long way, champsim::address pc)
{
  // Bimodal insertion with dynamic probability based on program phase
  uint8_t bip_probability;
  switch (program_phase) {
    case 0: bip_probability = 16; break;  // 1/16 for high locality
    case 1: bip_probability = 8; break;   // 1/8 for medium locality
    case 2: bip_probability = 4; break;   // 1/4 for low locality
    default: bip_probability = 8;         // Default 1/8
  }
  
  // Default value
  get_rrpv(set, way) = maxRRPV;
  get_signature(set, way) = hash_pc(pc);
  get_outcome(set, way) = pc_table[hash_pc(pc)];
  get_last_access_time(set, way) = current_time;
  get_access_count(set, way) = 1;
  
  // Occasionally insert with long re-reference prediction to preserve some fraction of the working set
  bip_counter++;
  if (bip_counter % bip_probability == 0) {
    get_rrpv(set, way) = maxRRPV - 1;
  }
}

void fundrip::update_srrip(long set, long way, champsim::address pc)
{
  // Static insertion with dynamic value based on predictors
  uint64_t pc_hash = hash_pc(pc);
  uint64_t new_sig = update_signature(0, pc);
  uint8_t pc_pred = pc_table[pc_hash];
  uint8_t sig_pred = signature_table[new_sig];
  
  // Combined prediction for insertion position
  uint8_t combined_pred = (pc_pred + sig_pred) / 2;
  uint8_t rrpv_value;
  
  if (combined_pred < 64) {
    rrpv_value = 0; // Predicted immediate reuse
  } else if (combined_pred < 192) {
    rrpv_value = maxRRPV - 2; // Predicted intermediate reuse
  } else {
    rrpv_value = maxRRPV - 1; // Predicted distant reuse
  }
  
  get_rrpv(set, way) = rrpv_value;
  get_signature(set, way) = new_sig;
  get_outcome(set, way) = combined_pred;
  get_last_access_time(set, way) = current_time;
  get_access_count(set, way) = 1;
}

void fundrip::update_adaptive(long set, long way, champsim::address pc, access_type type)
{
  // Advanced insertion policy that adapts based on multiple factors
  uint64_t pc_hash = hash_pc(pc);
  uint64_t new_sig = update_signature(0, pc);
  
  // Adjust prediction based on access type
  uint8_t base_rrpv;
  
  if (access_type{type} == access_type::PREFETCH) {
    // Prefetches start in the middle of the RRPV chain
    base_rrpv = PREFETCH_RRPV;
  } else {
    // Combine multiple predictors for demand accesses
    uint8_t pc_pred = pc_table[pc_hash];
    uint8_t sig_pred = signature_table[new_sig];
    uint8_t burst_pred = burst_table[pc_hash] > BURST_THRESHOLD ? 0 : 255;
    
    // Weighted prediction
    uint16_t combined = (pc_pred * 3 + sig_pred * 2 + burst_pred) / 6;
    
    if (combined < 64) {
      base_rrpv = 0; // Predicted immediate reuse
    } else if (combined < 128) {
      base_rrpv = 1; // Predicted near reuse
    } else if (combined < 192) {
      base_rrpv = 2; // Predicted intermediate reuse
    } else {
      base_rrpv = maxRRPV - 1; // Predicted distant reuse
    }
  }
  
  // Apply the prediction
  get_rrpv(set, way) = base_rrpv;
  get_signature(set, way) = new_sig;
  get_outcome(set, way) = pc_table[pc_hash];
  get_last_access_time(set, way) = current_time;
  get_access_count(set, way) = 1;
  
  // Update burst detector
  if (is_burst_access(pc)) {
    burst_table[pc_hash] = std::min(burst_table[pc_hash] + 1, static_cast<uint8_t>(15));
  } else {
    burst_table[pc_hash] = burst_table[pc_hash] > 0 ? burst_table[pc_hash] - 1 : 0;
  }
}

bool fundrip::should_bypass(champsim::address pc, long set)
{
  // Determine if we should bypass the cache for this address
  uint64_t pc_hash = hash_pc(pc);
  
  // Strong indication of no reuse
  if (pc_table[pc_hash] > BYPASS_THRESHOLD && program_phase == 2) {
    // Check if set is under pressure (all lines have high RRPV)
    bool set_pressure = true;
    for (long way = 0; way < NUM_WAY; way++) {
      if (get_rrpv(set, way) < maxRRPV - 1) {
        set_pressure = false;
        break;
      }
    }
    
    // Only bypass if set is under pressure
    return set_pressure;
  }
  
  return false;
}

void fundrip::track_reuse_distance(champsim::address addr)
{
  // Track reuse distance for addresses
  uint64_t page_addr = addr >> 12; // Track at page granularity
  
  // Check if address is in recent_accesses
  auto it = std::find(recent_accesses.begin(), recent_accesses.end(), page_addr);
  if (it != recent_accesses.end()) {
    // Found, calculate distance
    size_t distance = std::distance(recent_accesses.begin(), it);
    
    // Update reuse distance tracking
    reuse_dist[page_addr] = (reuse_dist[page_addr] + distance) / 2;
    
    // Remove old occurrence
    recent_accesses.erase(it);
  }
  
  // Add new occurrence
  recent_accesses.push_front(page_addr);
  if (recent_accesses.size() > ACCESS_HISTORY_SIZE) {
    recent_accesses.pop_back();
  }
}

bool fundrip::is_burst_access(champsim::address addr)
{
  // Check if this address is part of a burst access pattern
  uint64_t page_addr = addr >> 12;
  
  // Count occurrences in recent history
  int count = 0;
  for (auto& a : recent_accesses) {
    if (a == page_addr)
      count++;
    if (count >= BURST_THRESHOLD)
      return true;
  }
  
  return false;
}

// Called on every cache hit and cache fill
void fundrip::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, 
                                      champsim::address ip, champsim::address victim_addr, 
                                      access_type type, uint8_t hit)
{
  // Increment global time
  current_time++;
  
  // Track access pattern
  track_reuse_distance(full_addr);
  
  // Update program phase detection
  if (current_time % 1000 == 0) {
    detect_program_phase();
  }
  
  // Handle writeback access differently
  if (access_type{type} == access_type::WRITE) {
    if (!hit) {
      get_rrpv(set, way) = maxRRPV - 1; // Insert writebacks with long but not longest RRPV
      get_signature(set, way) = 0;
      get_last_access_time(set, way) = current_time;
      get_access_count(set, way) = 1;
    }
    return;
  }
  
  // Handle prefetch access differently
  if (access_type{type} == access_type::PREFETCH && !hit) {
    get_rrpv(set, way) = PREFETCH_RRPV; // Prefetches use intermediate RRPV
    get_signature(set, way) = update_signature(0, ip);
    get_last_access_time(set, way) = current_time;
    get_access_count(set, way) = 1;
    return;
  }
  
  // Update prediction tables
  update_pc_table(ip, hit);
  update_signature_table(get_signature(set, way), hit);
  
  // Cache hit
  if (hit) {
    // Promote to MRU with aging based on access pattern
    get_rrpv(set, way) = 0;
    
    // Update signature on hit
    get_signature(set, way) = update_signature(get_signature(set, way), ip);
    
    // Update outcome prediction
    get_outcome(set, way) = (get_outcome(set, way) >> 1); // Shift right to indicate likely reuse
    
    // Update access metadata
    get_access_count(set, way)++;
    get_last_access_time(set, way) = current_time;
    
    return;
  }
  
  // Cache miss processing
  auto begin = std::next(std::begin(rand_sets), triggering_cpu * NUM_POLICY * SDM_SIZE);
  auto end = std::next(begin, NUM_POLICY * SDM_SIZE);
  auto leader = std::find(begin, end, set);
  
  if (leader == end) { 
    // Follower sets
    auto selector = PSEL[triggering_cpu];
    if (selector.value() > (selector.maximum * 3 / 4)) { 
      // Strong BIP signal
      update_bip(set, way, ip);
    } else if (selector.value() > (selector.maximum / 4)) { 
      // Intermediate signal - use adaptive policy
      update_adaptive(set, way, ip, type);
    } else { 
      // Strong SRRIP signal
      update_srrip(set, way, ip);
    }
  } else if (leader == begin) { 
    // Leader 0: BIP
    // Make BIP policy more aggressive in reducing PSEL for stronger learning
    if (PSEL[triggering_cpu].value() > PSEL[triggering_cpu].minimum) {
      PSEL[triggering_cpu]--;
    }
    update_bip(set, way, ip);
  } else if (leader == std::next(begin)) { 
    // Leader 1: SRRIP
    // Make SRRIP policy more conservative in increasing PSEL for balanced learning
    if (PSEL[triggering_cpu].value() < PSEL[triggering_cpu].maximum) {
      PSEL[triggering_cpu]++;
    }
    update_srrip(set, way, ip);
  }
}

// Find replacement victim
long fundrip::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, 
                          const champsim::cache_block* current_set, 
                          champsim::address ip, champsim::address full_addr, 
                          access_type type)
{
  // Check if we should bypass caching
  if (access_type{type} == access_type::LOAD && should_bypass(ip, set)) {
    return NUM_WAY; // Return bypass signal
  }
  
  // First, look for invalid lines
  for (long way = 0; way < NUM_WAY; way++) {
    if (!current_set[way].valid)
      return way;
  }
  
  // Look for lines with maxRRPV
  std::vector<long> max_rrpv_ways;
  unsigned max_observed_rrpv = 0;
  
  for (long way = 0; way < NUM_WAY; way++) {
    unsigned current_rrpv = get_rrpv(set, way);
    
    if (current_rrpv > max_observed_rrpv) {
      max_observed_rrpv = current_rrpv;
      max_rrpv_ways.clear();
      max_rrpv_ways.push_back(way);
    } else if (current_rrpv == max_observed_rrpv) {
      max_rrpv_ways.push_back(way);
    }
  }
  
  // If we found ways with maxRRPV, select from them
  if (!max_rrpv_ways.empty()) {
    // If multiple candidates, use additional criteria
    if (max_rrpv_ways.size() > 1) {
      long best_way = max_rrpv_ways[0];
      uint64_t oldest_time = get_last_access_time(set, best_way);
      uint8_t lowest_count = get_access_count(set, best_way);
      uint8_t highest_outcome = get_outcome(set, best_way);
      
      for (size_t i = 1; i < max_rrpv_ways.size(); i++) {
        long way = max_rrpv_ways[i];
        
        // Prioritize lines with high outcome prediction (unlikely to be reused)
        if (get_outcome(set, way) > highest_outcome) {
          best_way = way;
          oldest_time = get_last_access_time(set, way);
          lowest_count = get_access_count(set, way);
          highest_outcome = get_outcome(set, way);
          continue;
        }
        
        // Then consider access count (prefer less accessed lines)
        if (get_outcome(set, way) == highest_outcome && get_access_count(set, way) < lowest_count) {
          best_way = way;
          oldest_time = get_last_access_time(set, way);
          lowest_count = get_access_count(set, way);
          continue;
        }
        
        // Finally consider recency (prefer older lines)
        if (get_outcome(set, way) == highest_outcome && 
            get_access_count(set, way) == lowest_count &&
            get_last_access_time(set, way) < oldest_time) {
          best_way = way;
          oldest_time = get_last_access_time(set, way);
        }
      }
      
      return best_way;
    }
    
    return max_rrpv_ways[0];
  }
  
  // If no lines have maxRRPV, age all lines and try again
  for (long way = 0; way < NUM_WAY; way++) {
    get_rrpv(set, way)++;
  }
  
  // After aging, the search should succeed
  return find_victim(triggering_cpu, instr_id, set, current_set, ip, full_addr, type);
}
