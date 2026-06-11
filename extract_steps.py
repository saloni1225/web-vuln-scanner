import json

transcript_path = r"C:\Users\Anmol\.gemini\antigravity\brain\d0230a13-7479-4e60-a82d-869f3e6a288a\.system_generated\logs\transcript.jsonl"

with open(transcript_path, "r", encoding="utf-8") as f:
    for line in f:
        try:
            data = json.loads(line)
            step = data.get("step_index")
            if 5210 <= step <= 5240:
                print(f"=== STEP {step} (type={data.get('type')}, source={data.get('source')}) ===")
                content = data.get("content")
                if content:
                    print(content[:1000])
                    if len(content) > 1000:
                        print("...")
                tool_calls = data.get("tool_calls", [])
                for call in tool_calls:
                    print(f"  Tool Call: {call.get('name')} -> {call.get('args', {}).get('CommandLine') or call.get('args', {}).get('AbsolutePath') or call.get('args', {}).get('TargetFile')}")
        except Exception as e:
            pass
