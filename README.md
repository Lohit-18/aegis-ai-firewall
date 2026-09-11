# Aegis: Real-Time LLM Prompt Injection Firewall 🛡️

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Framework: FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: OWASP LLM Top 10](https://img.shields.io/badge/Security-OWASP%20LLM01-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

> **A reverse-proxy security gateway that intercepts, sanitizes, and scores prompt injection attacks across untrusted data channels in real time.**

---

## 💡 Architectural Thesis

Language models treat all incoming input as a single, flat stream of tokens. Architecturally, an LLM **cannot distinguish** between authoritative developer instructions and malicious prompt injections contained within retrieved external data (e.g., PDFs, web scrapes, tool outputs).


**Aegis solves this at the network layer.** Sitting as a proxy between the client and the model, Aegis preserves provenance by inspecting incoming JSON payloads *before* they are collapsed into a flat token stream. Text is scored strictly according to its channel origin, applying aggressive mitigation to untrusted document channels while maintaining low friction for legitimate user prompts.

---

## ⚡ Key Features

* **Channel-Aware Provenance Inspection:** Maps API request roles (`system`, `user`, `tool`) to distinct trust channels (`SYSTEM`, `USER`, `DOCUMENT`) with independent threat baselines.
* **Noisy-OR Threat Scoring:** Utilizes a probabilistic combining function to aggregate risk weights without score saturation or hard clipping.
* **Structural & Unicode Normalization:** Unmasks obfuscation attacks by stripping zero-width codepoints (e.g., `U+200B`), decoding bidi overrides, and applying `NFKC` normalization before pattern execution.
* **Deterministic Fallback Routing:** Returns standardized HTTP `403 Forbidden` JSON responses upon threat threshold violation, protecting upstream LLM tokens.

---

## 🧮 Threat Scoring Model

Rather than using a naive additive sum—which causes weak rules to falsely outrank strong signals—Aegis computes the overall threat probability using a **Noisy-OR** function:

$$P(\text{Attack}) = 1 - \prod_{i=1}^{n} (1 - w_i)$$

Where $w_i$ represents the weight of each matched rule $i$.

### Properties of this Approach:
1. **Bounded:** Ensures the score mathematically approaches but never exceeds `1.0`.
2. **Monotonic:** Adding evidence strictly increases or maintains the threat score.
3. **Dominance-Preserving:** A single high-confidence rule (e.g., $w_i = 0.90$) independently triggers a block, regardless of low-confidence signals.

---

## 🛡️ Threat Model & Rule Table

Aegis targets **OWASP LLM01: Direct & Indirect Prompt Injection**.

| Rule ID | Vector Target | Severity | Weight ($w$) | Target Channels |
| :--- | :--- | :--- | :--- | :--- |
| `RULE_01_OVERRIDE` | Instruction Override / System Jailbreak | `HIGH` | `0.85` | `USER`, `DOCUMENT` |
| `RULE_02_EXFILTRATION` | Credential & System Prompt Leakage | `HIGH` | `0.75` | `USER`, `DOCUMENT` |
| `RULE_03_OBFUSCATION` | Invisible Codepoint / Structural Evasion | `MEDIUM` | `0.80` | `USER`, `DOCUMENT` |

---

## 🚀 Quickstart & Verification

### Prerequisites
* Python 3.11+
* Git

### 1. Installation

```bash
git clone [https://github.com/Lohit-18/aegis-ai-firewall.git](https://github.com/Lohit-18/aegis-ai-firewall.git)
cd aegis-ai-firewall

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate

# Install dependencies
pip install fastapi "uvicorn[standard]" httpx pydantic