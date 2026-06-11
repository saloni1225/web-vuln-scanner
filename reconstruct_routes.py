import json
import os

transcript_path = r"C:\Users\Anmol\.gemini\antigravity\brain\d0230a13-7479-4e60-a82d-869f3e6a288a\.system_generated\logs\transcript.jsonl"
base_file_path = r"c:\Users\Anmol\OneDrive\Desktop\web_scanner\adaptive-web-vuln-scanner\backend\api\routes.py"

# Read base file
with open(base_file_path, "r", encoding="utf-8") as f:
    content = f.read()

# Collect all edits chronologically
edits = []

with open(transcript_path, "r", encoding="utf-8") as f:
    for line in f:
        try:
            data = json.loads(line)
            tool_calls = data.get("tool_calls", [])
            for call in tool_calls:
                name = call.get("name")
                args = call.get("args", {})
                target = args.get("TargetFile") or args.get("Target")
                if target and "routes.py" in target:
                    if name == "replace_file_content":
                        edits.append({
                            "step": data.get("step_index"),
                            "type": "replace",
                            "target": args.get("TargetContent"),
                            "replacement": args.get("ReplacementContent")
                        })
                    elif name == "multi_replace_file_content":
                        chunks = args.get("ReplacementChunks", [])
                        if isinstance(chunks, str):
                            chunks = json.loads(chunks)
                        edits.append({
                            "step": data.get("step_index"),
                            "type": "multi",
                            "chunks": chunks
                        })
        except Exception as e:
            pass

print(f"Found {len(edits)} edits in transcript.")

# Let's apply them one by one
success_count = 0
failed_steps = []

for edit in edits:
    step = edit["step"]
    if edit["type"] == "replace":
        target = edit["target"]
        replacement = edit["replacement"]
        if isinstance(target, str) and isinstance(replacement, str):
            if target in content:
                content = content.replace(target, replacement, 1)
                print(f"Applied replace at step {step}")
                success_count += 1
            else:
                print(f"FAIL: Target not found at step {step}")
                failed_steps.append(step)
    elif edit["type"] == "multi":
        print(f"Processing multi-replace at step {step}...")
        all_ok = True
        temp_content = content
        chunks = edit["chunks"]
        if isinstance(chunks, str):
            try:
                chunks = json.loads(chunks)
            except Exception:
                pass
        
        # If chunks is still a string or list of strings, print it
        if not isinstance(chunks, list):
            print(f"FAIL: chunks is not a list at step {step}: {type(chunks)}")
            failed_steps.append(step)
            continue
            
        for chunk in chunks:
            if isinstance(chunk, str):
                try:
                    chunk = json.loads(chunk)
                except Exception:
                    print(f"FAIL: chunk is string but not valid json: {chunk}")
                    all_ok = False
                    continue
            
            target = chunk.get("TargetContent")
            replacement = chunk.get("ReplacementContent")
            if target in temp_content:
                temp_content = temp_content.replace(target, replacement, 1)
            else:
                all_ok = False
                print(f"  FAIL: Chunk target not found in step {step}")
        if all_ok:
            content = temp_content
            print(f"Applied multi-replace at step {step}")
            success_count += 1
        else:
            print(f"FAIL: Multi-replace failed to apply completely at step {step}")
            failed_steps.append(step)

# Save the reconstructed file
reconstructed_path = "reconstructed_routes.py"
with open(reconstructed_path, "w", encoding="utf-8") as f:
    f.write(content)

print(f"Reconstruction finished: {success_count} / {len(edits)} edits applied successfully.")
print(f"Failed steps: {failed_steps}")
