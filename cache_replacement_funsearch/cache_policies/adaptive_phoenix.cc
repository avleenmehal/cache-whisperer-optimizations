#include "adaptive_phoenix.h"
#include <algorithm>
#include <cassert>

adaptive_phoenix::adaptive_phoenix(CACHE* cache) : adaptive_phoenix(cache, cache->NUM_SET, cache->NUM_WAY) {}

adaptive_phoenix::adaptive_phoenix(CACHE* cache, long sets, long ways) : 
    replacement(cache), 
    NUM_WAY(ways), 
    last_used_cycles(static_cast<std::size_t>(sets * ways), 0),
    pc_history(static_cast<std::size_t>(sets * ways), 0),
    access_pattern(static_cast<std::size_t>(sets * ways), 0),
    bypass_candidate(static_cast<std::size_t>(sets * ways), false),
    victim_cache(static_cast<std::size_t>(sets), 0),
    set_conflicts(static_cast<std::size_t>(sets), 0) 
{
    // Initialize victim cache with invalid addresses
    std::fill(victim_cache.begin(), victim_cache.end(), (uint64_t)-1);
}

long adaptive_phoenix::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set,
                          champsim::address ip, champsim::address full_addr, access_type type)
{
    // Calculate start and end indices for the current set
    auto begin = std::next(std::begin(last_used_cycles), set * NUM_WAY);
    auto end = std::next(begin, NUM_WAY);
    
    // Find the best victim candidate based on multiple criteria
    long victim_way = -1;
    uint64_t max_score = 0;
    
    // Iterate through each way in the set
    for (long way = 0; way < NUM_WAY; ++way) {
        auto idx = begin + way;
        
        // Calculate the score based on:
        // 1. Recency of use (lower cycle is better)
        // 2. PC distance (if same PC, higher priority)
        // 3. Access pattern (sequential vs random)
        // 4. Bypass candidate status
        uint64_t score = last_used_cycles[idx];
        
        // Apply PC-based promotion if same program counter
        if (pc_history[idx] == ip) {
            score = std::max(score, cycle); // Promote to most recently used
        }
        
        // Demote blocks with sequential access patterns
        if (access_pattern[idx] == access_type::READ && 
            (instr_id - pc_history[idx]) > 32) {
            score = std::min(score, 0); // Demote if sequential access
        }
        
        // Bypass low-utility blocks
        if (bypass_candidate[idx]) {
            score = std::max(score, cycle); // Prioritize bypass candidates
        }
        
        // Track victim blocks in victim cache
        if (score > max_score) {
            max_score = score;
            victim_way = way;
        }
    }
    
    // Update victim cache with evicted blocks
    if (victim_way != -1) {
        victim_cache[set] = current_set[victim_way].address;
    }
    
    return victim_way;
}

void adaptive_phoenix::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, 
                                  champsim::address full_addr, champsim::address ip,
                                  champsim::address victim_addr, access_type type)
{
    // Update metadata for the filled block
    auto idx = static_cast<std::size_t>(set * NUM_WAY + way);
    last_used_cycles[idx] = cycle++;
    pc_history[idx] = ip;
    access_pattern[idx] = static_cast<uint64_t>(type);
    bypass_candidate[idx] = false;
}

void adaptive_phoenix::update_replacement_state(uint32_t triggering_cpu, long set, long way,
                                      champsim::address full_addr, champsim::address ip,
                                      champsim::address victim_addr, access_type type,
                                      uint8_t hit)
{
    if (hit && type != access_type::WRITE) {
        auto idx = static_cast<std::size_t>(set * NUM_WAY + way);
        last_used_cycles[idx] = cycle++;
        pc_history[idx] = ip;
        
        // Detect sequential patterns
        if (type == access_type::READ && 
            (instr_id - pc_history[idx]) <= 32) {
            access_pattern[idx] = access_type::SEQUENTIAL;
        }
        
        // Detect write-once patterns
        if (type == access_type::WRITE && 
            !is_write_once(set, way)) {
            bypass_candidate[idx] = true;
        }
    }
}

bool adaptive_phoenix::is_write_once(long set, long way) const {
    auto idx = static_cast<std::size_t>(set * NUM_WAY + way);
    return pc_history[idx] == 0 || 
           (access_pattern[idx] == access_type::WRITE && 
            (cycle - last_used_cycles[idx]) > 1000);
}
