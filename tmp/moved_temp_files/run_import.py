with open("import_debug.txt", "w") as f:
    f.write("Script started...\n")

print("Attempting import of web.app...")
import web.app
print("Import successful!")

with open("import_debug.txt", "a") as f:
    f.write("Script finished!\n")
