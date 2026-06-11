import json

transcript_path = r"C:\Users\Anmol\.gemini\antigravity\brain\d0230a13-7479-4e60-a82d-869f3e6a288a\.system_generated\logs\transcript.jsonl"

with open(transcript_path, "r", encoding="utf-8") as f:
    for line in f:
        try:
            data = json.loads(line)
            tool_calls = data.get("tool_calls", [])
            for call in tool_calls:
                name = call.get("name")
                args = call.get("args", {})
                cmd = args.get("CommandLine")
                if cmd and "git " in cmd:
                    print(f"Step {data.get('step_index')}: {cmd}")
        except Exception as e:
            pass
