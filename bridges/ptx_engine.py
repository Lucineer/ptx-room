#!/usr/bin/env python3
"""PTX room engine — compiles PTX, evaluates constraints, updates agent profiles."""
import yaml, subprocess, tempfile, os, json
from pathlib import Path

def load_room():
    with open("world/rooms/ptx-lab.yaml") as f:
        return yaml.safe_load(f)

def load_agent(name):
    path = Path(f"world/agents/{name}.yaml")
    if path.exists():
        with open(path) as f:
            return yaml.safe_load(f)
    return None

def save_agent(name, data):
    with open(f"world/agents/{name}.yaml", "w") as f:
        yaml.dump(data, f, default_flow_style=False)

def compile_ptx(ptx_code):
    """Compile PTX, return (success, output, error)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ptx", delete=False) as f:
        f.write(ptx_code)
        ptx_file = f.name
    
    try:
        # Try to compile with nvcc
        result = subprocess.run(
            ["nvcc", "-ptx", "-o", "/dev/null", ptx_file],
            capture_output=True, text=True
        )
        return result.returncode == 0, result.stdout, result.stderr
    finally:
        os.unlink(ptx_file)

def evaluate_constraint(constraint, ptx_code):
    """Evaluate a single constraint gate."""
    # For now, just check compilation
    if constraint["id"] == "syntax":
        success, out, err = compile_ptx(ptx_code)
        return {
            "passes": success,
            "error": 0.0 if success else 1.0,
            "output": out,
            "error_msg": err
        }
    # Placeholder for other constraints
    return {"passes": True, "error": 0.0, "output": "", "error_msg": ""}

def process_turn():
    """Process all pending commands."""
    room = load_room()
    
    # Find command files
    command_files = list(Path("world/commands").glob("*.yaml"))
    for cmd_file in command_files:
        with open(cmd_file) as f:
            cmd = yaml.safe_load(f)
        
        agent = cmd.get("agent")
        ptx = cmd.get("ptx")
        
        if not agent or not ptx:
            continue
        
        # Load or create agent profile
        profile = load_agent(agent) or {
            "name": agent,
            "room": "ptx-lab",
            "stats": {"turns_completed": 0, "snap_accuracy": 0.0, "avg_tightening_rounds": 0.0, "mastery_level": 0},
            "learned_patterns": [],
            "ptx_instincts": []
        }
        
        # Sequential constraint tightening
        constraints = room["constraints"]
        current_ptx = ptx
        tightening_rounds = 0
        
        for constraint in constraints:
            result = evaluate_constraint(constraint, current_ptx)
            tightening_rounds += 1
            
            if not result["passes"]:
                # Constraint failed — agent needs to tighten
                # For now, just record failure
                profile["stats"]["snap_accuracy"] = max(0, profile["stats"]["snap_accuracy"] - 0.1)
                break
            else:
                profile["stats"]["snap_accuracy"] = min(1.0, profile["stats"]["snap_accuracy"] + 0.05)
        
        # Update stats
        profile["stats"]["turns_completed"] += 1
        profile["stats"]["avg_tightening_rounds"] = (
            (profile["stats"]["avg_tightening_rounds"] * (profile["stats"]["turns_completed"] - 1) + tightening_rounds)
            / profile["stats"]["turns_completed"]
        )
        
        # Mastery level based on snap accuracy
        if profile["stats"]["snap_accuracy"] > 0.8:
            profile["stats"]["mastery_level"] = 3
        elif profile["stats"]["snap_accuracy"] > 0.6:
            profile["stats"]["mastery_level"] = 2
        elif profile["stats"]["snap_accuracy"] > 0.4:
            profile["stats"]["mastery_level"] = 1
        
        save_agent(agent, profile)
        
        # Log the turn
        log_entry = {
            "turn": cmd_file.stem,
            "agent": agent,
            "tightening_rounds": tightening_rounds,
            "final_snap_accuracy": profile["stats"]["snap_accuracy"],
            "mastery_level": profile["stats"]["mastery_level"],
            "timestamp": subprocess.run(["date", "-Iseconds"], capture_output=True, text=True).stdout.strip()
        }
        
        log_file = Path("world/logs") / f"{cmd_file.stem}.json"
        with open(log_file, "w") as f:
            json.dump(log_entry, f, indent=2)
        
        # Remove processed command
        cmd_file.unlink()
    
    # Update room stats
    room["state"]["total_compilations"] += len(command_files)
    with open("world/rooms/ptx-lab.yaml", "w") as f:
        yaml.dump(room, f, default_flow_style=False)

if __name__ == "__main__":
    process_turn()
