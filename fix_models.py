import os
import sys

models_path = os.path.join(os.path.dirname(__file__), "src", "models.py")

with open(models_path, "r", encoding="utf-8") as f:
    text = f.read()

# Make sure BigInteger is imported
if "BigInteger" not in text:
    text = text.replace("Integer, String", "Integer, BigInteger, String")

# Fix foreign keys to bigints
text = text.replace("Column(Integer, ForeignKey('assets.id'", "Column(BigInteger, ForeignKey('assets.id'")
text = text.replace("Column(Integer, ForeignKey('scans.id'", "Column(BigInteger, ForeignKey('scans.id'")

with open(models_path, "w", encoding="utf-8") as f:
    f.write(text)

print("Updated models.py!")
