import json

transcript_path = r"C:\Users\Anmol\.gemini\antigravity\brain\d0230a13-7479-4e60-a82d-869f3e6a288a\.system_generated\logs\transcript.jsonl"

with open(transcript_path, "r", encoding="utf-8") as f:
    for line in f:
        try:
            data = json.loads(line)
            content = data.get("content", "")
            if "assume-unchanged" in content or "skip-worktree" in content:
                print(f"Step {data.get('step_index')}:")
                print(content[:500])
        except Exception as e:
            pass
