import os
import re

def main():
    filepath = r"c:\Users\saura\OneDrive - betterlivings international school\Downloads\Code\molten-rocket-quantum_scanner\src\database.py"
    if not os.path.exists(filepath):
        print("[!] file not found.")
        return
        
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    print("[*] Fixing cursor calls...")
    
    # Add import at the top after other imports
    if "import pymysql.cursors" not in content:
        content = content.replace("import sys", "import sys\nimport pymysql.cursors")
        
    original_size = len(content)
    
    # Match both conn.cursor(dictionary=True) and chain_cur = conn.cursor(dictionary=True)
    content = content.replace(".cursor(dictionary=True)", ".cursor(pymysql.cursors.DictCursor)")
    
    if len(content) != original_size:
        print(f"[✅] Cursor calls updated.")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
    else:
        print("[*] No cursor changes made.")

if __name__ == "__main__":
    main()
