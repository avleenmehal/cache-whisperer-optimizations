
import os
import subprocess
import random
import json
import time
import numpy as np
from typing import List, Dict, Any, Tuple
from groq import Groq
import shutil

CHAMPSIM_PATH = "ChampSim"  # Update this with your ChampSim path
GROQ_API_KEY = "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"  # Set your OpenAI API key here or use environment variables
TRACES_PATH = "ChampSim/traces"      # Path to ChampSim trace files
OUTPUT_PATH = "./cache_policies"     # Where to store generated policies
NUM_GENERATIONS = 1                 # Number of generations to run
POPULATION_SIZE = 1                  # Number of policies per generation
EVALUATION_CYCLES = 50000000         # Simulation cycles for evaluation


def compile_policy( policy_name: str) -> bool:
    """Compile the policy with ChampSim"""
    policy = {'name':policy_name,'compilation_success':False}

    # Paths to your generated files and ChampSim dirs
    policy_file   = os.path.join(OUTPUT_PATH, f"{policy_name}.cc")
    header_file   = os.path.join(OUTPUT_PATH, f"{policy_name}.h")
    repl_root     = os.path.join(CHAMPSIM_PATH, "replacement")

    try:

        # 3) Decide which build to run
        build_script = os.path.join(CHAMPSIM_PATH, "build_champsim.sh")
        if os.path.isfile(build_script):
            # Sacusa fork build
            cmd = f"{build_script} bimodal no no no no {policy_name} 1"
            proc = subprocess.run(cmd,
                                shell=True,
                                cwd=CHAMPSIM_PATH,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        else:
            # Official upstream:
            #   a) Write a temporary JSON config
            cfg = {
                    "executable_name": policy_name,
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
                        "replacement": policy_name
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

            cfg_path = os.path.join(CHAMPSIM_PATH, f"{policy_name}_cfg.json")
            filepath = os.path.join(f"{policy_name}_cfg.json")
            import pathlib
            #cfg_path = pathlib.Path(CHAMPSIM_PATH) / f"{policy_name}_cfg.json"
            #cfg_path_unix = cfg_path.as_posix()
            with open(cfg_path, "w") as f:
                json.dump(cfg, f, indent=2)

            #   b) Run config.sh and make
            subprocess.run("make clean",
                                shell=True,
                                cwd=CHAMPSIM_PATH,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
            subprocess.run(f"./config.sh {filepath}",
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
            print(f"Successfully compiled {policy_name}")
            return True
        else:
            print(f"Build failed for {policy_name}:\n{proc.stderr.decode().strip()}")
            return False

    except Exception as e:
        print(f"Error during compilation of {policy_name}: {e}")
        return False

#compile_policy('lru_reference')

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


import re 
def parse_simulation_results(output_file: str) -> Tuple[float, float]:
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
    
import re
from typing import Tuple, Optional

def parse_simulation_results(output_file: str) -> Tuple[Optional[float], Optional[float], Optional[int], Optional[int], Optional[int]]:
    """
    Parse MPKI, IPC, and LLC stats (ACCESS, HIT, MISS) from ChampSim output file.

    Returns:
        Tuple of (MPKI, IPC, LLC_ACCESS, LLC_HIT, LLC_MISS)
    """
    try:
        with open(output_file, "r") as f:
            content = f.read()

            # IPC
            ipc_match = re.search(r'CPU 0 cumulative IPC: ([\d\.]+) instructions:', content)

            # MPKI
            mpki_match = re.search(r'MPKI: ([\d\.]+)', content)

            # LLC TOTAL line
            llc_match = re.search(
                r'cpu0->LLC TOTAL\s+ACCESS:\s+(\d+)\s+HIT:\s+(\d+)\s+MISS:\s+(\d+)',
                content
            )

            if ipc_match and mpki_match and llc_match:
                ipc = float(ipc_match.group(1))
                mpki = float(mpki_match.group(1))
                llc_access = int(llc_match.group(1))
                llc_hit = int(llc_match.group(2))
                llc_miss = int(llc_match.group(3))
                return mpki, ipc, llc_access, llc_hit, llc_miss

    except Exception as e:
        print(f"Error parsing results from {output_file}: {str(e)}")

    return None, None, None, None, None

def evaluate_policy(policy_name: str) -> float:
    """Evaluate the performance of a compiled policy using ChampSim"""
    policy = CachePolicy('test', policy_name)
    
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
            binary_path = os.path.join(CHAMPSIM_PATH, "bin", f"{policy_name}")
            trace_path = os.path.join(TRACES_PATH, trace)
            output_file = os.path.join(OUTPUT_PATH, f"{policy_name}_{trace}_output.txt")
            
            # Run simulation
            print(f"Evaluating {policy_name} on {trace}...")
            command = f"{binary_path} --warmup_instructions 20000000 --simulation_instructions {EVALUATION_CYCLES} {trace_path} > {output_file}"
            process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if process.returncode != 0:
                print(f"Error running simulation: {process.stderr.decode()}")
                continue
            
            # Parse results
            mpki, ipc, llc_access, llc_hit, llc_miss = parse_simulation_results(output_file)
            print(mpki, ipc, llc_access, llc_hit, llc_miss)
            
            if llc_miss is not None and ipc is not None:
                results[trace] = {"mpki": llc_miss, "ipc": ipc}
    
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

compile_policy('lru')
evaluate_policy('lru')