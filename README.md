\# Aegis: AI Prompt Injection Firewall 🛡️



A real-time, channel-aware reverse proxy that intercepts, analyzes, and sanitizes traffic between user applications and Large Language Models (LLMs) to prevent prompt injection and data exfiltration.



\## Why This Exists (The Core Thesis)

A language model receives one flat sequence of tokens. It has no mechanism for telling instructions written by the developer apart from text that arrived inside an untrusted document. 



A proxy sitting in front of the model \*does\* know the difference. Aegis treats user inputs (semi-trusted) and retrieved documents (untrusted) differently to stop prompt injection at the network layer before the model ever sees it.



\## Key Features

\* \*\*Channel-Aware Provenance:\*\* Scores payloads differently based on their origin (`system`, `user`, or `document`).

\* \*\*Noisy-OR Threat Combiner:\*\* Combines rule weights mathematically `P(attack) = 1 − Π (1 − wᵢ)` rather than simple addition, preventing score saturation while allowing single high-severity rules to flag attacks.

\* \*\*Structural Obfuscation Detection:\*\* Detects and normalizes hidden Unicode characters (like zero-width joiners) commonly used to bypass regex filters.



\## How It Works

1\. Intercepts the raw JSON payload headed to the LLM.

2\. Maps each message to a strict trust channel.

3\. Cleans invisible characters and logs obfuscation attempts.

4\. Scans the normalized text against a weighted rule table.

5\. Emits a `BLOCK` or `ALLOW` verdict based on a dynamically calculated threat score.

