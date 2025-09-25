
"""
Configuration file for the FunSearch Cache Optimizer
"""

# ChampSim paths
CHAMPSIM_PATH = "/path/to/champsim"  # Update this with your ChampSim path
TRACES_PATH = "/path/to/traces"      # Path to ChampSim trace files
OUTPUT_PATH = "./cache_policies"     # Where to store generated policies

# OpenAI API configuration
OPENAI_API_KEY = "your-api-key"      # Set your OpenAI API key here or use environment variables
OPENAI_MODEL = "gpt-4o"              # Model to use for policy generation

# Evolution parameters
NUM_GENERATIONS = 10                 # Number of generations to run
POPULATION_SIZE = 5                  # Number of policies per generation
PARENT_SELECTION_SIZE = 2            # Number of parents to select for each new policy
TOURNAMENT_SIZE = 3                  # Number of candidates in tournament selection

# Simulation parameters
WARMUP_INSTRUCTIONS = 10000000       # Warmup instructions for simulation
EVALUATION_CYCLES = 50000000         # Simulation cycles for evaluation
NUM_TRACES_TO_EVALUATE = 3           # Number of traces to use for evaluation (random sample)

# Policy generation parameters
GENERATION_TEMPERATURE = 0.8         # Higher values for more creative/diverse policies
CROSSOVER_TEMPERATURE = 0.7          # Temperature for combining parent policies
HEADER_TEMPERATURE = 0.2             # Lower temperature for precise header generation

# Fitness calculation weights
MPKI_WEIGHT = 1.0                    # Weight for MPKI in fitness calculation (negative)
IPC_WEIGHT = 0.1                     # Weight for IPC in fitness calculation (positive)
