with open("src/models.py", "r") as f:
    text = f.read()

text = text.replace(r"\'sqlite\'", '"sqlite"')

with open("src/models.py", "w") as f:
    f.write(text)
