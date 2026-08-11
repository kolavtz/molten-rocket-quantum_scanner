import subprocess
import csv

def main():
    try:
        output = subprocess.check_output(
            'wmic process where "name=\'python.exe\'" get ProcessId,CommandLine /format:csv',
            shell=True,
            text=True
        )
        print("--- RAW FIRST LINE ---")
        lines = output.strip().splitlines()
        if lines:
            print(f"Header/Line 0: {repr(lines[0])}")
            if len(lines) > 1:
                print(f"Line 1: {repr(lines[1])}")
                
            reader = csv.reader(lines)
            for i, row in enumerate(reader):
                print(f"Row {i}: {row}")
                if i > 2:
                     break
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
