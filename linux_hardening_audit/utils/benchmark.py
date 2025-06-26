import json
from pathlib import Path

def load_benchmark(name):
    """Load benchmark checks from JSON file"""
    path = Path(__file__).parent.parent / "benchmarks" / f"{name}.json"
    with open(path) as f:
        return json.load(f)
