import json

transcript_path = r"C:\Users\Anmol\.gemini\antigravity\brain\d0230a13-7479-4e60-a82d-869f3e6a288a\.system_generated\logs\transcript.jsonl"

with open(transcript_path, "r", encoding="utf-8") as f:
    for line in f:
        try:
            data = json.loads(line)
            if data.get("step_index") == 2409:
                tool_calls = data.get("tool_calls", [])
                for call in tool_calls:
                    name = call.get("name")
                    args = call.get("args", {})
                    code = args.get("CodeContent")
                    if code:
                        with open("recovered_routes_step_2409_raw.py", "w", encoding="utf-8") as out:
                            out.write(code)
                        print("Saved CodeContent from Step 2409 to recovered_routes_step_2409_raw.py")
        except Exception as e:
            pass
