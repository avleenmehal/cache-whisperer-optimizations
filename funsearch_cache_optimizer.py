
import os
import subprocess
import random
import json
import time
import numpy as np
from typing import List, Dict, Any, Tuple
from groq import Groq
import shutil
# Configuration
CHAMPSIM_PATH = "../ChampSim"  # Update this with your ChampSim path
GROQ_API_KEY = "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"      # Set your OpenAI API key here or use environment variables
TRACES_PATH = "traces/astar_163B.trace.xz"      # Path to ChampSim trace files
OUTPUT_PATH = "./cache_policies"     # Where to store generated policies
NUM_GENERATIONS = 4                 # Number of generations to run
POPULATION_SIZE = 5                  # Number of policies per generation
EVALUATION_CYCLES = 500000         # Simulation cycles for evaluation

# Initialize OpenAI client
# openai.api_key = GROQ_API_KEY
client = Groq(api_key=GROQ_API_KEY)

class CachePolicy:
    """Represents a cache replacement policy implementation"""
    def __init__(self, code: str, name: str, parent_policies: List[str] = None):
        self.code = code
        self.name = name
        self.parent_policies = parent_policies or []
        self.fitness = None
        self.compilation_success = False
        self.metrics = {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "code": self.code,
            "fitness": self.fitness,
            "parent_policies": self.parent_policies,
            "compilation_success": self.compilation_success,
            "metrics": self.metrics
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CachePolicy':
        policy = cls(code=data["code"], name=data["name"], parent_policies=data["parent_policies"])
        policy.fitness = data.get("fitness")
        policy.compilation_success = data.get("compilation_success", False)
        policy.metrics = data.get("metrics", {})
        return policy

class FunSearchCacheOptimizer:
    """Main class for running the FunSearch optimization process"""
    
    def __init__(self):
        self.all_policies = {}  # Dictionary of all policies by name
        self.generations = []   # List of generations, each containing policy names
        os.makedirs(OUTPUT_PATH, exist_ok=True)
        
        # Load the reference implementation
        self.reference_policy = self.load_reference_policy()
    
    def load_reference_policy(self) -> CachePolicy:
        """Load the reference DRRIP implementation"""
        # You could also read this from a file
        reference_code = """
#include "drrip.h"

#include <algorithm>
#include <cassert>
#include <random>
#include <utility>

#include "champsim.h"

drrip::drrip(CACHE* cache) : replacement(cache), NUM_SET(cache->NUM_SET), NUM_WAY(cache->NUM_WAY), rrpv(static_cast<std::size_t>(NUM_SET * NUM_WAY))
{
  // randomly selected sampler sets
  std::size_t TOTAL_SDM_SETS = NUM_CPUS * NUM_POLICY * SDM_SIZE;
  std::generate_n(std::back_inserter(rand_sets), TOTAL_SDM_SETS, std::knuth_b{1});
  std::sort(std::begin(rand_sets), std::end(rand_sets));
  std::fill_n(std::back_inserter(PSEL), NUM_CPUS, typename decltype(PSEL)::value_type{0});
}

unsigned& drrip::get_rrpv(long set, long way) { return rrpv.at(static_cast<std::size_t>(set * NUM_WAY + way)); }

void drrip::update_bip(long set, long way)
{
  get_rrpv(set, way) = maxRRPV;

  bip_counter++;
  if (bip_counter == BIP_MAX) {
    bip_counter = 0;
    get_rrpv(set, way) = maxRRPV - 1;
  }
}

void drrip::update_srrip(long set, long way) { get_rrpv(set, way) = maxRRPV - 1; }

// called on every cache hit and cache fill
void drrip::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                     champsim::address victim_addr, access_type type, uint8_t hit)
{
  // do not update replacement state for writebacks
  if (access_type{type} == access_type::WRITE) {
    get_rrpv(set, way) = maxRRPV - 1;
    return;
  }

  // cache hit
  if (hit) {
    get_rrpv(set, way) = 0; // for cache hit, DRRIP always promotes a cache line to the MRU position
    return;
  }

  // cache miss
  auto begin = std::next(std::begin(rand_sets), triggering_cpu * NUM_POLICY * SDM_SIZE);
  auto end = std::next(begin, NUM_POLICY * SDM_SIZE);
  auto leader = std::find(begin, end, set);

  if (leader == end) { // follower sets
    auto selector = PSEL[triggering_cpu];
    if (selector.value() > (selector.maximum / 2)) { // follow BIP
      update_bip(set, way);
    } else { // follow SRRIP
      update_srrip(set, way);
    }
  } else if (leader == begin) { // leader 0: BIP
    PSEL[triggering_cpu]--;
    update_bip(set, way);
  } else if (leader == std::next(begin)) { // leader 1: SRRIP
    PSEL[triggering_cpu]++;
    update_srrip(set, way);
  }
}

// find replacement victim
long drrip::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                        champsim::address full_addr, access_type type)
{
  // look for the maxRRPV line
  auto begin = std::next(std::begin(rrpv), set * NUM_WAY);
  auto end = std::next(begin, NUM_WAY);

  auto victim = std::max_element(begin, end);
  if (auto rrpv_update = maxRRPV - *victim; rrpv_update != 0)
    for (auto it = begin; it != end; ++it)
      *it += rrpv_update;

  assert(begin <= victim);
  assert(victim < end);
  return std::distance(begin, victim); // cast protected by assertions
}
"""
        reference_header = """
#ifndef DRRIP_H
#define DRRIP_H

#include <vector>
#include <deque>
#include <unordered_map>
#include <array>
#include <limits>
#include <cstdint>

#include "cache.h"
#include "replacement.h"
#include "champsim.h"

class drrip : public replacement
{
private:
  const std::size_t NUM_SET;
  const std::size_t NUM_WAY;
  
  // DRRIP constants
  static constexpr unsigned int maxRRPV = 3;
  static constexpr unsigned int NUM_POLICY = 2;
  static constexpr unsigned int SDM_SIZE = 32;
  static constexpr unsigned int BIP_MAX = 32;
  
  // Cache line states
  std::vector<unsigned> rrpv;
  
  // Set dueling mechanism
  std::vector<long> rand_sets;
  std::vector<saturating_counter<8>> PSEL;
  
  unsigned int bip_counter = 0;
  
  unsigned& get_rrpv(long set, long way);
  void update_bip(long set, long way);
  void update_srrip(long set, long way);

public:
  drrip(CACHE* cache);

  long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, 
                   champsim::address ip, champsim::address full_addr, access_type type) override;
                   
  void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, 
                               champsim::address ip, champsim::address victim_addr, access_type type, uint8_t hit) override;
};

#endif // DRRIP_H
"""
        policy = CachePolicy(code=reference_code, name="drrip_reference")
        self.all_policies["drrip_reference"] = policy
        
        # Save the header file for reference
        with open(os.path.join(OUTPUT_PATH, "drrip.h"), "w") as f:
            f.write(reference_header)
            
        return policy
    
    def generate_initial_population(self) -> List[str]:
        """Generate the initial population of cache policies"""
        policies = []
        
        # Define the LLM prompt to generate the initial population
        prompt = """
You are a cache replacement policy expert. I want you to create a new cache replacement policy for the ChampSim simulator that improves upon the DRRIP (Dynamic Re-Reference Interval Prediction) policy.

Your replacement policy should focus on optimizing these aspects:
1. Better prediction of re-reference patterns
2. More efficient handling of different access patterns
3. Enhanced victim selection logic
4. Improved set dueling mechanism
5. Lower MPKI (Misses Per Kilo Instructions)

Here is the reference implementation of DRRIP:

```cpp
{reference_code}
```

Generate a completely new implementation with a unique class name. The policy should be based on the same structure but have improved logic. Include both .h and .cc files.
Your implementation must be compatible with ChampSim and must compile with C++17.

Make the policy innovative, focusing on incorporating techniques like:
- PC-based prediction
- Access pattern tracking
- Program phase detection
- Dynamic adaptation
- Signature-based patterns
- Bypassing for low-utility blocks

Name your class something unique, not drrip. Include detailed comments explaining your innovations.
"""
        
        for i in range(POPULATION_SIZE):
            print(f"Generating policy {i+1}/{POPULATION_SIZE}...")
            
            # Generate a policy using the LLM
            response = client.chat.completions.create(
                model = "llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a cache replacement policy expert specializing in C++ implementations for ChampSim."},
                    {"role": "user", "content": prompt.format(reference_code=self.reference_policy.code)}
                ],
                temperature=0.8,  # Higher temperature for more diversity
                max_tokens=4000
            )
            
            # Extract the code from the response
            generated_text = response.choices[0].message.content
            
            # Parse the header and implementation files
            policy_code = self.extract_code(generated_text)
            
            if policy_code:
                policy_name = self.extract_policy_name(policy_code)
                policy = CachePolicy(code=policy_code, name=f"{policy_name}_gen0_{i}")
                self.all_policies[policy.name] = policy
                policies.append(policy.name)
                
                # Save the policy code to file
                with open(os.path.join(OUTPUT_PATH, f"{policy.name}.cc"), "w") as f:
                    f.write(policy_code)
            else:
                print(f"Failed to extract code for policy {i+1}")
        
        self.generations.append(policies)
        return policies
    
    def extract_code(self, text: str) -> str:
        """Extract code blocks from the generated text"""
        # Extract code between ```cpp and ```
        import re
        cpp_blocks = re.findall(r'```cpp\n(.*?)```', text, re.DOTALL)
        
        if not cpp_blocks:
            # Try without the language specifier
            cpp_blocks = re.findall(r'```\n(.*?)```', text, re.DOTALL)
        
        if cpp_blocks:
            # Find the .cc implementation file
            for block in cpp_blocks:
                if "update_replacement_state" in block and "find_victim" in block:
                    return block
                    
        return None
    
    def extract_policy_name(self, code: str) -> str:
        """Extract the policy class name from the code"""
        import re
        # Try to find class name pattern
        match = re.search(r'class\s+(\w+)\s*:', code)
        if match:
            return match.group(1)
            
        # Fallback to a default name
        return f"policy_{random.randint(1000, 9999)}"
    


    def compile_policy(self, policy_name: str) -> bool:
        """Compile the policy with ChampSim"""
        policy = self.all_policies[policy_name]
        policy.compilation_success = False

        # Paths to your generated files and ChampSim dirs
        policy_file   = os.path.join(OUTPUT_PATH, f"{policy_name}.cc")
        header_file   = os.path.join(OUTPUT_PATH, f"{policy_name}.h")
        repl_root     = os.path.join(CHAMPSIM_PATH, "replacement")

        try:
            # 1) Create a subdirectory for this policy
            policy_dir = os.path.join(repl_root, policy.name)
            os.makedirs(policy_dir, exist_ok=True)

            # 2) Copy the .cc and .h into that subdirectory
            shutil.copy(policy_file, os.path.join(policy_dir, f"{policy.name}.cc"))
            # regenerate header just in case
            self.generate_header_file(policy_name)
            shutil.copy(header_file, os.path.join(policy_dir, f"{policy.name}.h"))

            # 3) Decide which build to run
            build_script = os.path.join(CHAMPSIM_PATH, "build_champsim.sh")
            if os.path.isfile(build_script):
                # Sacusa fork build
                cmd = f"{build_script} bimodal no no no no {policy.name} 1"
                proc = subprocess.run(cmd,
                                    shell=True,
                                    cwd=CHAMPSIM_PATH,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            else:
                # Official upstream:
                #   a) Write a temporary JSON config
                cfg = {
                        "executable_name": policy.name,
                        "block_size": 64,
                        "page_size": 4096,
                        "heartbeat_frequency": 10000000,
                        "num_cores": 1,

                        "ooo_cpu": [
                            {
                                "frequency": 4000,
                                "ifetch_buffer_size":64,
                                "decode_buffer_size":32,
                                "dispatch_buffer_size":32,
                                "register_file_size":128,
                                "rob_size": 352,
                                "lq_size": 128,
                                "sq_size": 72,
                                "fetch_width": 6,
                                "decode_width": 6,
                                "dispatch_width": 6,
                                "execute_width": 4,
                                "lq_width": 2,
                                "sq_width": 2,
                                "retire_width": 5,
                                "mispredict_penalty": 1,
                                "scheduler_size": 128,
                                "decode_latency": 1,
                                "dispatch_latency": 1,
                                "schedule_latency": 0,
                                "execute_latency": 0,
                                "branch_predictor": "bimodal",
                                "btb": "basic_btb"
                            }
                        ],

                        "DIB": {
                            "window_size": 16,
                            "sets": 32,
                            "ways": 8
                        },

                        "L1I": {
                            "sets": 64,
                            "ways": 8,
                            "rq_size": 64,
                            "wq_size": 64,
                            "pq_size": 32,
                            "mshr_size": 8,
                            "latency": 4,
                            "max_tag_check": 2,
                            "max_fill": 2,
                            "prefetch_as_load": False,
                            "virtual_prefetch": True,
                            "prefetch_activate": "LOAD,PREFETCH",
                            "prefetcher": "no"
                        },

                        "L1D": {
                            "sets": 64,
                            "ways": 12,
                            "rq_size": 64,
                            "wq_size": 64,
                            "pq_size": 8,
                            "mshr_size": 16,
                            "latency": 5,
                            "max_tag_check": 2,
                            "max_fill": 2,
                            "prefetch_as_load": False,
                            "virtual_prefetch": False,
                            "prefetch_activate": "LOAD,PREFETCH",
                            "prefetcher": "no"
                        },

                        "L2C": {
                            "sets": 1024,
                            "ways": 8,
                            "rq_size": 32,
                            "wq_size": 32,
                            "pq_size": 16,
                            "mshr_size": 32,
                            "latency": 10,
                            "max_tag_check": 1,
                            "max_fill": 1,
                            "prefetch_as_load": False,
                            "virtual_prefetch": False,
                            "prefetch_activate": "LOAD,PREFETCH",
                            "prefetcher": "no"
                        },

                        "ITLB": {
                            "sets": 16,
                            "ways": 4,
                            "rq_size": 16,
                            "wq_size": 16,
                            "pq_size": 0,
                            "mshr_size": 8,
                            "latency": 1,
                            "max_tag_check": 2,
                            "max_fill": 2,
                            "prefetch_as_load": False
                        },

                        "DTLB": {
                            "sets": 16,
                            "ways": 4,
                            "rq_size": 16,
                            "wq_size": 16,
                            "pq_size": 0,
                            "mshr_size": 8,
                            "latency": 1,
                            "max_tag_check": 2,
                            "max_fill": 2,
                            "prefetch_as_load": False
                        },

                        "STLB": {
                            "sets": 128,
                            "ways": 12,
                            "rq_size": 32,
                            "wq_size": 32,
                            "pq_size": 0,
                            "mshr_size": 16,
                            "latency": 8,
                            "max_tag_check": 1,
                            "max_fill": 1,
                            "prefetch_as_load": False
                        },

                        "PTW": {
                        "pscl5_set": 1,
                        "pscl5_way": 2,
                        "pscl4_set": 1,
                        "pscl4_way": 4,
                        "pscl3_set": 2,
                        "pscl3_way": 4,
                        "pscl2_set": 4,
                        "pscl2_way": 8,
                        "rq_size": 16,
                        "mshr_size": 5,
                        "max_read": 2,
                        "max_write": 2
                        },

                        "LLC": {
                            "frequency": 4000,
                            "sets": 2048,
                            "ways": 16,
                            "rq_size": 32,
                            "wq_size": 32,
                            "pq_size": 32,
                            "mshr_size": 64,
                            "latency": 20,
                            "max_tag_check": 1,
                            "max_fill": 1,
                            "prefetch_as_load": False,
                            "virtual_prefetch": False,
                            "prefetch_activate": "LOAD,PREFETCH",
                            "prefetcher": "no",
                            "replacement": policy.name
                        },

                        "physical_memory": {
                            "data_rate": 3200,
                            "channels": 1,
                            "ranks": 1,
                            "bankgroups": 8,
                            "banks": 4,
                            "bank_rows": 65536,
                            "bank_columns": 1024,
                            "channel_width": 8,
                            "wq_size": 64,
                            "rq_size": 64,
                            "tCAS":  24,
                            "tRCD": 24,
                            "tRP": 24,
                            "tRAS": 52,
                            "refresh_period": 32,
                            "refreshes_per_period": 8192
                        },

                        "virtual_memory": {
                            "pte_page_size": 4096,
                            "num_levels": 5,
                            "minor_fault_penalty": 200,
                            "randomization": 1
                        }
                        }

                cfg_path = os.path.join(CHAMPSIM_PATH, f"{policy.name}_cfg.json")
                with open(cfg_path, "w") as f:
                    json.dump(cfg, f, indent=2)

                #   b) Run config.sh and make
                subprocess.run(f"./config.sh {cfg_path}",
                            shell=True,
                            cwd=CHAMPSIM_PATH,
                            check=True)
                proc = subprocess.run("make -j",
                                    shell=True,
                                    cwd=CHAMPSIM_PATH,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            # 4) Check build result
            if proc.returncode == 0:
                policy.compilation_success = True
                print(f"Successfully compiled {policy.name}")
                return True
            else:
                print(f"Build failed for {policy.name}:\n{proc.stderr.decode().strip()}")
                return False

        except Exception as e:
            print(f"Error during compilation of {policy_name}: {e}")
            return False

    
    
    # def compile_policy(self, policy_name: str) -> bool:
    #     """Compile the policy with ChampSim"""
    #     policy = self.all_policies[policy_name]
        
    #     # Create a temporary directory for compilation
    #     temp_dir = os.path.join(OUTPUT_PATH, f"temp_{policy_name}")
    #     os.makedirs(temp_dir, exist_ok=True)
        
    #     # Copy the policy file to ChampSim's replacement directory
    #     policy_file = os.path.join(OUTPUT_PATH, f"{policy_name}.cc")
    #     champsim_replacement_dir = os.path.join(CHAMPSIM_PATH, "replacement")
        
        
        
    #     try:
    #         # Copy policy file to ChampSim
    #         subprocess.run(["cp", policy_file, champsim_replacement_dir], check=True)
            
    #         # Generate the header file
    #         self.generate_header_file(policy_name)
            
    #         # Copy header file to ChampSim
    #         header_file = os.path.join(OUTPUT_PATH, f"{policy_name}.h")
    #         subprocess.run(["cp", header_file, champsim_replacement_dir], check=True)
            
    #         # Build ChampSim with the new policy
    #         os.chdir(CHAMPSIM_PATH)
            
    #         # code added
    #         #####################################################
    #         if os.path.isfile("build_champsim.sh"):
    #             # existing Sacusa‐fork build
    #             build_cmd = f"./build_champsim.sh bimodal no no no no {policy_name} 1"
    #             proc = subprocess.run(build_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #         else:
    #             # official upstream build
    #             # 1) write a temp JSON config
    #             cfg = {
    #                 "BPT":  {"branch_predictor": "bimodal"},
    #                 "L1D":  {"prefetcher": "no"},
    #                 "L2C":  {"prefetcher": "no"},
    #                 "LLC":  {"replacement": policy_name},
    #                 "NUM_CORE": 1
    #             }
    #             cfg_path = os.path.join(CHAMPSIM_PATH, f"{policy_name}_cfg.json")
    #             with open(cfg_path, "w") as f:
    #                 json.dump(cfg, f, indent=2)
    #             # 2) run config.sh + make
    #             subprocess.run(f"./config.sh {cfg_path}", shell=True, check=True)
    #             proc = subprocess.run("make -j", shell=True, check=False)
    #         if proc.returncode == 0:
    #             policy.compilation_success = True
    #             return True
    #         else:
    #             print("Build failed:", proc.stderr.decode())
    #             return False

    #         #######################################################
            
            
            
    #         # build_command = f"./build_champsim.sh bimodal no no no no {policy_name} 1"
    #         # process = subprocess.run(build_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
    #         # if process.returncode == 0:
    #         #     policy.compilation_success = True
    #         #     print(f"Successfully compiled {policy_name}")
    #         #     return True
    #         # else:
    #         #     print(f"Failed to compile {policy_name}: {process.stderr.decode()}")
    #         #     return False
                
    #     except Exception as e:
    #         print(f"Error during compilation of {policy_name}: {str(e)}")
    #         return False
            
    #     finally:
    #         # Clean up temporary directory
    #         subprocess.run(["rm", "-rf", temp_dir])
    
    def generate_header_file(self, policy_name: str) -> None:
        """Generate a header file for the policy based on the implementation"""
        policy = self.all_policies[policy_name]
        
        # Use LLM to generate a matching header file
        prompt = f"""
Based on the following C++ implementation of a cache replacement policy for ChampSim, create a matching header (.h) file:

```cpp
{policy.code}
```

The header file should:
1. Define the class with all necessary methods
2. Declare all member variables used in the implementation
3. Include all required headers
4. Use proper include guards
5. Match the class name and method signatures exactly as used in the implementation

Return only the header file code.
"""
        
        response = client.chat.completions.create(
            model = "llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a C++ expert who creates header files based on implementation code."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2  # Lower temperature for more precise output
        )
        
        header_code = response.choices[0].message.content
        
        # Extract the code from markdown if needed
        import re
        cpp_blocks = re.findall(r'```cpp\n(.*?)```', header_code, re.DOTALL)
        if cpp_blocks:
            header_code = cpp_blocks[0]
        else:
            # Try without the language specifier
            cpp_blocks = re.findall(r'```\n(.*?)```', header_code, re.DOTALL)
            if cpp_blocks:
                header_code = cpp_blocks[0]
        
        # Save the header file
        with open(os.path.join(OUTPUT_PATH, f"{policy_name}.h"), "w") as f:
            f.write(header_code)
    
    def evaluate_policy(self, policy_name: str) -> float:
        """Evaluate the performance of a compiled policy using ChampSim"""
        policy = self.all_policies[policy_name]
        
        if not policy.compilation_success:
            print(f"Cannot evaluate {policy_name}: Compilation failed")
            policy.fitness = float('-inf')
            return float('-inf')
        
        results = {}
        try:
            # Get list of trace files
            traces = [f for f in os.listdir(TRACES_PATH) if f.endswith(".trace.xz")]
            if not traces:
                print(f"No trace files found in {TRACES_PATH}")
                policy.fitness = float('-inf')
                return float('-inf')
            
            # Use a subset of traces for faster evaluation
            traces = random.sample(traces, min(3, len(traces)))
            
            for trace in traces:
                # Run ChampSim with the policy
                binary_path = os.path.join(CHAMPSIM_PATH, "bin", f"bimodal-no-no-no-no-{policy_name}-1core")
                trace_path = os.path.join(TRACES_PATH, trace)
                output_file = os.path.join(OUTPUT_PATH, f"{policy_name}_{trace}_output.txt")
                
                # Run simulation
                print(f"Evaluating {policy_name} on {trace}...")
                command = f"{binary_path} -warmup_instructions 10000000 -simulation_instructions {EVALUATION_CYCLES} {trace_path} > {output_file}"
                process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if process.returncode != 0:
                    print(f"Error running simulation: {process.stderr.decode()}")
                    continue
                
                # Parse results
                mpki, ipc = self.parse_simulation_results(output_file)
                
                if mpki is not None and ipc is not None:
                    results[trace] = {"mpki": mpki, "ipc": ipc}
        
        except Exception as e:
            print(f"Error during evaluation of {policy_name}: {str(e)}")
            policy.fitness = float('-inf')
            return float('-inf')
        
        # Calculate fitness score (lower MPKI and higher IPC is better)
        if results:
            avg_mpki = sum(r["mpki"] for r in results.values()) / len(results)
            avg_ipc = sum(r["ipc"] for r in results.values()) / len(results)
            
            # Combined fitness score: prioritize MPKI reduction but also reward IPC improvements
            fitness = -avg_mpki + (0.1 * avg_ipc)
            
            # Store metrics
            policy.metrics = {
                "avg_mpki": avg_mpki,
                "avg_ipc": avg_ipc,
                "traces": results
            }
            
            policy.fitness = fitness
            print(f"Policy {policy_name} evaluated: MPKI={avg_mpki:.2f}, IPC={avg_ipc:.2f}, Fitness={fitness:.4f}")
            return fitness
        
        policy.fitness = float('-inf')
        return float('-inf')
    
    def parse_simulation_results(self, output_file: str) -> Tuple[float, float]:
        """Parse MPKI and IPC from ChampSim output file"""
        try:
            with open(output_file, "r") as f:
                content = f.read()
                
                # Parse MPKI (misses per kilo instructions)
                mpki_match = re.search(r'LLC TOTAL[\s\S]*?MPKI: ([\d\.]+)', content)
                
                # Parse IPC (instructions per cycle)
                ipc_match = re.search(r'CPU 0 cumulative IPC: ([\d\.]+)', content)
                
                if mpki_match and ipc_match:
                    mpki = float(mpki_match.group(1))
                    ipc = float(ipc_match.group(1))
                    return mpki, ipc
        
        except Exception as e:
            print(f"Error parsing results from {output_file}: {str(e)}")
        
        return None, None
    
    def select_parents(self, generation: List[str], num_parents: int = 2) -> List[str]:
        """Select parents using tournament selection"""
        # Calculate fitness for all policies in the generation
        for policy_name in generation:
            if self.all_policies[policy_name].fitness is None:
                self.evaluate_policy(policy_name)
        
        # Filter out policies with invalid fitness scores
        valid_policies = [p for p in generation if self.all_policies[p].fitness != float('-inf')]
        
        if len(valid_policies) < num_parents:
            # Not enough valid policies, supplement with reference
            valid_policies.append("drrip_reference")
        
        # Tournament selection
        parents = []
        for _ in range(num_parents):
            if not valid_policies:
                break
                
            # Select random candidates for the tournament
            tournament_size = min(3, len(valid_policies))
            tournament = random.sample(valid_policies, tournament_size)
            
            # Select the best policy from the tournament
            best_policy = max(tournament, key=lambda p: self.all_policies[p].fitness)
            parents.append(best_policy)
            
            # Remove the selected policy to prevent duplicate selection
            valid_policies.remove(best_policy)
        
        return parents
    
    def generate_new_policy(self, parents: List[str], generation_num: int, policy_idx: int) -> str:
        """Generate a new policy through 'crossover' using the LLM"""
        parent_policies = [self.all_policies[p] for p in parents]
        
        # Create a prompt that includes the parent policies
        parent_codes = "\n\n".join([f"Parent {i+1} ({p.name}, fitness: {p.fitness:.4f}):\n```cpp\n{p.code}\n```" 
                                   for i, p in enumerate(parent_policies)])
        
        # Add information about what made the parents successful
        strengths = ""
        for i, parent in enumerate(parent_policies):
            if parent.metrics:
                strengths += f"\nParent {i+1} strengths:\n"
                strengths += f"- Average MPKI: {parent.metrics.get('avg_mpki', 'N/A')}\n"
                strengths += f"- Average IPC: {parent.metrics.get('avg_ipc', 'N/A')}\n"
        
        prompt = f"""
You are a cache replacement policy expert. Create a new cache replacement policy that combines the strengths of these parent policies:

{parent_codes}

{strengths}

Generate a new policy that:
1. Combines the best features from both parents
2. Introduces at least one innovative improvement
3. Focuses on reducing cache misses (MPKI)
4. Has a unique class name

Your implementation should be compatible with ChampSim and compile with C++17.
Focus on optimizing how the cache decides which blocks to evict when new data needs to be cached.

Return ONLY the implementation (.cc) file content. The header will be automatically generated.
"""
        

        # Generate a new policy using the LLM
        
        response = client.chat.completions.create(
            model = "llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a cache replacement policy expert specializing in C++ implementations for ChampSim."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7  # Balance between innovation and reliability
        )
        print(response.choices[0].message.content)
        # response = openai.chat.completions.create(
        #     model="gpt-4o",
        #     messages=[
        #         {"role": "system", "content": "You are a cache replacement policy expert specializing in C++ implementations for ChampSim."},
        #         {"role": "user", "content": prompt}
        #     ],
        #     temperature=0.7  # Balance between innovation and reliability
        # )
        
        # Extract the code from the response
        generated_text = response.choices[0].message.content
        policy_code = self.extract_code(generated_text)
        
        if policy_code:
            policy_name = self.extract_policy_name(policy_code)
            # Ensure unique name by adding generation and index
            unique_name = f"{policy_name}_gen{generation_num}_{policy_idx}"
            
            policy = CachePolicy(
                code=policy_code, 
                name=unique_name, 
                parent_policies=parents
            )
            
            self.all_policies[unique_name] = policy
            
            # Save the policy code to file
            with open(os.path.join(OUTPUT_PATH, f"{unique_name}.cc"), "w") as f:
                f.write(policy_code)
                
            return unique_name
        else:
            print("Failed to extract code for new policy")
            # Return a random parent as fallback
            return random.choice(parents)
    
    def run(self) -> None:
        """Run the FunSearch optimization process"""
        # Generate initial population
        print("Generating initial population...")
        current_generation = self.generate_initial_population()
        
        # Evaluate reference policy
        print("Evaluating reference policy...")
        self.compile_policy("drrip_reference")
        self.evaluate_policy("drrip_reference")
        reference_fitness = self.all_policies["drrip_reference"].fitness
        print(f"Reference policy fitness: {reference_fitness}")
        
        # Run generations
        for gen in range(NUM_GENERATIONS):
            print(f"\n=== Generation {gen+1}/{NUM_GENERATIONS} ===")
            
            # Compile and evaluate all policies in the current generation
            for policy_name in current_generation:
                if self.all_policies[policy_name].compilation_success is False:
                    success = self.compile_policy(policy_name)
                    if not success:
                        continue
                
                if self.all_policies[policy_name].fitness is None:
                    self.evaluate_policy(policy_name)
            
            # Save checkpoint
            self.save_checkpoint(f"generation_{gen}")
            
            # Generate new population
            new_generation = []
            for i in range(POPULATION_SIZE):
                # Select parents
                parents = self.select_parents(current_generation)
                if not parents:
                    print("No suitable parents found, using reference policy")
                    parents = ["drrip_reference"]
                
                # Generate new policy
                new_policy = self.generate_new_policy(parents, gen+1, i)
                new_generation.append(new_policy)
            
            # Update current generation
            current_generation = new_generation
            self.generations.append(current_generation)
            
            # Print generation summary
            self.print_generation_summary(gen)
        
        # Find the best policy across all generations
        best_policy_name = self.find_best_policy()
        print(f"\n=== Best Policy: {best_policy_name} ===")
        best_policy = self.all_policies[best_policy_name]
        
        if best_policy.fitness is not None:
            improvement = ((best_policy.fitness - reference_fitness) / abs(reference_fitness)) * 100
            print(f"Fitness: {best_policy.fitness:.4f} (Improvement: {improvement:.2f}%)")
            
            if best_policy.metrics:
                print(f"MPKI: {best_policy.metrics.get('avg_mpki', 'N/A')}")
                print(f"IPC: {best_policy.metrics.get('avg_ipc', 'N/A')}")
        
        # Save final results
        self.save_checkpoint("final_results")
    
    def find_best_policy(self) -> str:
        """Find the policy with the best fitness across all generations"""
        valid_policies = {name: policy for name, policy in self.all_policies.items() 
                          if policy.fitness is not None and policy.fitness != float('-inf')}
        
        if not valid_policies:
            return "drrip_reference"
        
        return max(valid_policies.items(), key=lambda x: x[1].fitness)[0]
    
    def print_generation_summary(self, generation_num: int) -> None:
        """Print a summary of the current generation"""
        current_gen = self.generations[generation_num]
        
        print(f"\nGeneration {generation_num} Summary:")
        print("-" * 60)
        print(f"{'Policy Name':<30} {'Fitness':<10} {'MPKI':<8} {'IPC':<8}")
        print("-" * 60)
        
        for policy_name in current_gen:
            policy = self.all_policies[policy_name]
            fitness = policy.fitness if policy.fitness is not None else "N/A"
            
            if isinstance(fitness, float):
                fitness_str = f"{fitness:.4f}"
            else:
                fitness_str = str(fitness)
                
            mpki = policy.metrics.get('avg_mpki', 'N/A') if policy.metrics else 'N/A'
            ipc = policy.metrics.get('avg_ipc', 'N/A') if policy.metrics else 'N/A'
            
            if isinstance(mpki, float):
                mpki_str = f"{mpki:.2f}"
            else:
                mpki_str = str(mpki)
                
            if isinstance(ipc, float):
                ipc_str = f"{ipc:.2f}"
            else:
                ipc_str = str(ipc)
                
            print(f"{policy_name:<30} {fitness_str:<10} {mpki_str:<8} {ipc_str:<8}")
    
    def save_checkpoint(self, checkpoint_name: str) -> None:
        """Save the current state of the optimization process"""
        checkpoint = {
            "generations": self.generations,
            "policies": {name: policy.to_dict() for name, policy in self.all_policies.items()}
        }
        
        with open(os.path.join(OUTPUT_PATH, f"{checkpoint_name}.json"), "w") as f:
            json.dump(checkpoint, f, indent=2)
    
    def load_checkpoint(self, checkpoint_path: str) -> None:
        """Load a saved checkpoint"""
        with open(checkpoint_path, "r") as f:
            checkpoint = json.load(f)
            
        self.generations = checkpoint["generations"]
        self.all_policies = {name: CachePolicy.from_dict(policy_data) 
                            for name, policy_data in checkpoint["policies"].items()}

if __name__ == "__main__":
    # Check if required paths exist
    if not os.path.exists(CHAMPSIM_PATH):
        print(f"ERROR: ChampSim path {CHAMPSIM_PATH} does not exist. Please update CHAMPSIM_PATH.")
        exit(1)
        
    if not os.path.exists(TRACES_PATH):
        print(f"ERROR: Traces path {TRACES_PATH} does not exist. Please update TRACES_PATH.")
        exit(1)
    
    print("Starting FunSearch Cache Optimizer...")
    optimizer = FunSearchCacheOptimizer()
    optimizer.run()
    print("Optimization complete. Results saved to", OUTPUT_PATH)
