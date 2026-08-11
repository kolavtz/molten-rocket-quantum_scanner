import os

dir_path = r'c:\Users\saura\Downloads\hf-proj\molten-rocket-quantum_scanner\web\blueprints'
files = [f for f in os.listdir(dir_path) if f.startswith('api_') and f.endswith('.py')]

for filename in files:
    filepath = os.path.join(dir_path, filename)
    with open(filepath, 'r', encoding='utf-8') as f:
         content = f.read()

    if 'from src.db import SessionLocal' in content:
         new_content = content.replace(
              'from src.db import SessionLocal',
              'from src.db import db_session as SessionLocal'
         )
         with open(filepath, 'w', encoding='utf-8') as f:
              f.write(new_content)
         print(f"Patched import in {filename}")

print("Import fixing attempt complete.")
