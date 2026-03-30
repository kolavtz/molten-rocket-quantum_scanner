with open('server_boot_out.txt', 'r', encoding='utf-16') as f:
    text = f.read()

with open('server_boot_out_utf8.txt', 'w', encoding='utf-8') as f:
    f.write(text)

print("Transcoded to server_boot_out_utf8.txt")
