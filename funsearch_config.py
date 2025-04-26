
"""
Configuration file for the FunSearch Cache Optimizer
"""

# ChampSim paths
CHAMPSIM_PATH = "/path/to/champsim"  # Update this with your ChampSim path
TRACES_PATH = "/path/to/traces"      # Path to ChampSim trace files
OUTPUT_PATH = "./cache_policies"     # Where to store generated policies

# Model configuration
MODEL_NAME = "EleutherAI/gpt-neo-1.3B"  # Changed from OpenAI to GPT-Neo
DEVICE = "cuda"  # Use "cpu" if no GPU available
MAX_LENGTH = 2048
TEMPERATURE = 0.8

# Evolution parameters
NUM_GENERATIONS = 10                 # Number of generations to run
POPULATION_SIZE = 5                  # Number of policies per generation
PARENT_SELECTION_SIZE = 2            # Number of parents to select for each new policy
TOURNAMENT_SIZE = 3                  # Number of candidates in tournament selection

# Simulation parameters
WARMUP_INSTRUCTIONS = 10000000       # Warmup instructions for simulation
EVALUATION_CYCLES = 50000000         # Simulation cycles for evaluation
NUM_TRACES_TO_EVALUATE = 3           # Number of traces to use for evaluation

# Example successful policies for few-shot prompting
EXAMPLE_POLICIES = [
    {
        "name": "hawkeye",
        "description": "PC-based cache replacement policy",
        "code": """
#include "hawkeye.h"
#include <vector>
#include <unordered_map>

class hawkeye : public replacement {
private:
    std::vector<unsigned> rrpv;
    std::unordered_map<uint64_t, bool> pc_prediction;
    
public:
    hawkeye(CACHE* cache) : 
        replacement(cache),
        rrpv(cache->NUM_SET * cache->NUM_WAY, 3) {}
        
    void update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way,
                                uint64_t full_addr, uint64_t pc, uint64_t victim_addr,
                                uint32_t type, uint8_t hit) override {
        if (hit) {
            rrpv[set * NUM_WAY + way] = 0;
            return;
        }
        
        bool prediction = predict_reuse(pc);
        rrpv[set * NUM_WAY + way] = prediction ? 0 : 3;
        update_predictor(pc, prediction);
    }
    
    uint32_t find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set,
                        const BLOCK* current_set, uint64_t pc,
                        uint64_t full_addr, uint32_t type) override {
        for (uint32_t way = 0; way < NUM_WAY; way++) {
            if (rrpv[set * NUM_WAY + way] == 3)
                return way;
        }
        
        for (uint32_t way = 0; way < NUM_WAY; way++)
            rrpv[set * NUM_WAY + way]++;
            
        return find_victim(cpu, instr_id, set, current_set, pc, full_addr, type);
    }
};
        """
    },
    {
        "name": "ship",
        "description": "Signature-based Hit Predictor cache replacement",
        "code": """
#include "ship.h"
#include <vector>
#include <bitset>

class ship : public replacement {
private:
    std::vector<unsigned> rrpv;
    std::vector<std::bitset<16>> signatures;
    
public:
    ship(CACHE* cache) : 
        replacement(cache),
        rrpv(cache->NUM_SET * cache->NUM_WAY, 3),
        signatures(cache->NUM_SET * cache->NUM_WAY) {}
        
    void update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way,
                                uint64_t full_addr, uint64_t pc, uint64_t victim_addr,
                                uint32_t type, uint8_t hit) override {
        if (hit) {
            rrpv[set * NUM_WAY + way] = 0;
            update_signature(set, way, pc);
            return;
        }
        
        signatures[set * NUM_WAY + way] = calculate_signature(pc);
        rrpv[set * NUM_WAY + way] = predict_reuse(signatures[set * NUM_WAY + way]) ? 1 : 3;
    }
    
    uint32_t find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set,
                        const BLOCK* current_set, uint64_t pc,
                        uint64_t full_addr, uint32_t type) override {
        for (uint32_t way = 0; way < NUM_WAY; way++) {
            if (rrpv[set * NUM_WAY + way] == 3)
                return way;
        }
        
        for (uint32_t way = 0; way < NUM_WAY; way++)
            rrpv[set * NUM_WAY + way]++;
            
        return find_victim(cpu, instr_id, set, current_set, pc, full_addr, type);
    }
};
        """
    }
]

