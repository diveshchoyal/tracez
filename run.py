import os
import subprocess
import sys

if __name__ == "__main__":
    # Launch backend/run.py inside the backend directory to isolate sys.path and prevent module conflicts
    backend_dir = os.path.join(os.path.dirname(__file__), "backend")
    runner_script = os.path.join(backend_dir, "run.py")
    
    if not os.path.exists(runner_script):
        print(f"[!] Error: Runner script not found at {runner_script}")
        sys.exit(1)
        
    try:
        # Spawn the child python process with working directory set to backend/
        sys.exit(subprocess.call([sys.executable, runner_script], cwd=backend_dir))
    except KeyboardInterrupt:
        print("\n[*] Shutting down TraceZ server.")
        sys.exit(0)


