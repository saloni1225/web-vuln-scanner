# AI Copilot Report

AdaptiveScan includes an AI Copilot backend abstraction for exposure operations and executive communication.

## Implemented

- `/api/ai/copilot`
- Provider abstraction for local, Hugging Face, and OpenAI-compatible providers
- Capability catalog
- Evidence-grounded response contract

## Capabilities

- Risk prioritization
- Finding deduplication
- Executive summaries
- Remediation suggestions
- Exposure explanations
- Attack path explanation
- Exploitability prediction

## Remaining Production Work

- Add tenant-scoped retrieval over reports, findings, assets, and attack paths.
- Add Hugging Face model configuration.
- Add UI copilot panel with prompt history and citations.
