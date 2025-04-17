
#ifndef FUNDRIP_H
#define FUNDRIP_H

#include <vector>
#include <deque>
#include <unordered_map>
#include <array>
#include <limits>
#include <cstdint>

#include "cache.h"
#include "replacement.h"
#include "champsim.h"

class fundrip : public replacement
{
private:
  const std::size_t NUM_SET;
  const std::size_t NUM_WAY;
  
  // Enhanced prediction constants
  static constexpr unsigned int maxRRPV = 3;
  static constexpr unsigned int NUM_POLICY = 2;
  static constexpr unsigned int SDM_SIZE = 32;
  static constexpr unsigned int BIP_MAX = 32;
  static constexpr unsigned int HISTORY_SIZE = 8;
  static constexpr unsigned int ACCESS_HISTORY_SIZE = 256;
  static constexpr unsigned int BURST_THRESHOLD = 3;
  static constexpr unsigned int SIGNATURE_SIZE = 12;
  static constexpr unsigned int COUNTER_BITS = 8;
  static constexpr unsigned int PREFETCH_RRPV = 2;
  static constexpr unsigned int BYPASS_THRESHOLD = 224;
  
  // Cache line states
  std::vector<unsigned> rrpv;                        // RRPV values for each line
  std::vector<uint64_t> signature;                   // PC signature for each line
  std::vector<uint8_t> outcome;                      // Outcome prediction for each line
  std::vector<uint64_t> last_access_time;            // Last access time for each line
  std::vector<uint8_t> access_count;                 // Access count for each line
  
  // Prediction tables
  std::vector<uint8_t> pc_table;                     // PC-based prediction table
  std::vector<uint8_t> signature_table;              // Signature-based prediction table
  std::vector<uint8_t> burst_table;                  // Burst access detection table
  
  // Set dueling mechanism
  std::vector<long> rand_sets;                       // Random sampler sets
  std::vector<saturating_counter<8>> PSEL;           // Policy selector
  
  // Access pattern tracking
  std::deque<champsim::address> recent_accesses;     // Recent access history
  std::unordered_map<uint64_t, uint8_t> reuse_dist;  // Reuse distance tracking
  uint64_t current_time;                             // Current access time counter
  uint16_t bip_counter;                              // BIP throttling counter
  uint8_t program_phase;                             // Current program phase
  
  // Utility functions
  unsigned& get_rrpv(long set, long way);
  uint64_t& get_signature(long set, long way);
  uint8_t& get_outcome(long set, long way);
  uint64_t& get_last_access_time(long set, long way);
  uint8_t& get_access_count(long set, long way);
  uint64_t hash_pc(champsim::address pc);
  uint64_t update_signature(uint64_t old_sig, champsim::address pc);
  void update_pc_table(champsim::address pc, bool hit);
  void update_signature_table(uint64_t sig, bool hit);
  void detect_program_phase();
  void update_bip(long set, long way, champsim::address pc);
  void update_srrip(long set, long way, champsim::address pc);
  void update_adaptive(long set, long way, champsim::address pc, access_type type);
  bool should_bypass(champsim::address pc, long set);
  void track_reuse_distance(champsim::address addr);
  bool is_burst_access(champsim::address addr);

public:
  fundrip(CACHE* cache);

  long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, 
                   champsim::address ip, champsim::address full_addr, access_type type) override;
                   
  void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, 
                               champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit) override;
};

#endif // FUNDRIP_H
