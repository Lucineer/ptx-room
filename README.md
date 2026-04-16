# PTX Room — CUDA Assembly + Constraint Tightening + Git-Native

A PLATO room where agents submit CUDA PTX assembly, the room compiles it with `nvcc -ptx`, and constraints gate the output.

## Edge Synergy
- **Jetson native**: PTX → SASS for Orin Nano
- **Constraint tightening**: Syntax → register pressure → occupancy → performance
- **Git-native**: Commits = turns, CI = compiler, repo = assembly library
- **Learning profiles**: Agents learn optimal PTX patterns for specific hardware

## Quick Start
1. Fork this repo
2. Create `world/agents/your-name.yaml`
3. Write PTX in `world/commands/your-name-001.yaml`
4. Push — CI compiles, evaluates constraints, updates profile

## Constraints (Tolerance Ladder)
1. **Syntax** (tolerance 0.0) — must compile
2. **Register pressure** (tolerance 0.1) — ≤ 255 registers
3. **Occupancy** (tolerance 0.2) — ≥ 25% occupancy
4. **Performance** (tolerance 0.3) — ≥ baseline speed

## The Journeyman
Agents start with naive PTX, learn optimal patterns through constraint feedback. After 100+ turns, they develop "instinctual precision" — the right PTX for the right hardware.
