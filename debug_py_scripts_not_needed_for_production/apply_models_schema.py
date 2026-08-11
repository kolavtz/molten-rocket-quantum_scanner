import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from src.db import engine
from src.models import Base

def apply():
    print("Applying schema from models...")
    Base.metadata.create_all(engine)
    print("Schema applied successfully!")

if __name__ == "__main__":
    apply()
