import re

input_path = r"c:\Users\Anmol\OneDrive\Desktop\web_scanner\adaptive-web-vuln-scanner\recovered_routes_step_5223.txt"
output_path = r"c:\Users\Anmol\OneDrive\Desktop\web_scanner\adaptive-web-vuln-scanner\cleaned_routes_first_800.py"

with open(input_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

cleaned_lines = []
for line in lines:
    # Match lines like "8: 1: import uuid" or "10: 3: from fastapi..."
    # The first number and colon is from the view_file tool output,
    # the second number and colon is the original line number.
    match = re.match(r"^\d+:\s+(\d+):\s?(.*)$", line)
    if match:
        orig_line_num = int(match.group(1))
        content = match.group(2)
        cleaned_lines.append((orig_line_num, content))

# Sort by original line number to ensure correct order
cleaned_lines.sort(key=lambda x: x[0])

with open(output_path, "w", encoding="utf-8") as f:
    for num, content in cleaned_lines:
        f.write(content + "\n")

print(f"Cleaned and saved {len(cleaned_lines)} lines to {output_path}")
