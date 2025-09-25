#include "lru_aura.h"
#include <algorithm>
#include <cassert>
#include <map>

using namespace champsim::modules::replacement;

lru_aura::lru_aura(CACHE* cache) : lru_aura(cache, cache->NUM_SET, cache->NUM_WAY) {}

lru_aura::lru_aura(CACHE* cache, long sets, long ways) : replacement(cache), NUM_WAY(ways)
{
    // Initialize metadata for all cache blocks
    metadata.resize(sets * ways);
    for (auto& block : metadata) {
        block.last_used_cycle = 0;
        block.access_count = 0;
    }
}

long lru_aura::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set,
                   champsim::address ip, champsim::address full_addr, access_type type)
{
    const auto begin = std::next(std::begin(metadata), set * NUM_WAY);
    const auto end = std::next(begin, NUM_WAY);
    
    // Find the best victim block using Aura's multi-criteria selection
    auto victim = begin;
    uint64_t max_score = 0;
    
    // Evaluate each block's potential as a victim candidate
    for (auto it = begin; it < end; ++it) {
        // Calculate a score based on inverse of various factors
        uint64_t score = 0;
        
        // Prefer blocks with older last_used_cycle (temporal locality)
        score += cycle - it->last_used_cycle;
        
        // Prefer blocks with lower access frequency (temporal stability)
        score += (cycle / it->access_count) * 2;  // Weight frequency more heavily
        
        // Prefer blocks not associated with recent program counters
        score += it->pc_access_count[ip] << 1;    // Weight PC history
        
        // Update victim if current block has higher score
        if (score > max_score) {
            max_score = score;
            victim = it;
        }
    }
    
    // Calculate the victim way within the set
    return std::distance(begin, victim);
}

void lru_aura::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr,
                             champsim::address ip, champsim::address victim_addr, access_type type)
{
    const auto block_idx = set * NUM_WAY + way;
    auto& block = metadata[block_idx];
    
    // Update metadata when a new block is inserted
    block.last_used_cycle = cycle++;
    block.access_count++;
    
    // Track program counter access patterns
    block.pc_access_count[ip] = cycle++;
}

void lru_aura::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr,
                               champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit)
{
    if (hit && type != access_type::WRITE) {  // Skip for writeback hits
        const auto block_idx = set * NUM_WAY + way;
        auto& block = metadata[block_idx];
        
        // Update metadata on cache hit
        block.last_used_cycle = cycle++;
        block.access_count++;
        block.pc_access_count[ip] = cycle++;
    }
}
