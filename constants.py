# constants.py
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BLACKLIST_FILE = os.path.join(SCRIPT_DIR, "data", "blacklist.json")
REQUIRED_DPIS = [None, 120, 160, 240, 320, 480]
