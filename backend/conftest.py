import sys
from pathlib import Path

# Automatically ensure backend folder is in Python search path during testing
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
