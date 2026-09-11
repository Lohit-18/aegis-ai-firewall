import re
from enum import Enum
from typing import List, Union, Dict, Any
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI()

# 1. Define channels
class Channel(str, Enum):
    SYSTEM = "system"
    USER = "user"
    DOCUMENT = "document"

# 2. Rule definition (Pattern, Weight, Severity)
DETECTION_RULES = [
    {
        "id": "RULE_01_OVERRIDE",
        "pattern": r"(?i)ignore\s+(all\s+)?(previous\s+)?instructions",
        "weight": 0.85,  # 85% confidence if matched alone
        "severity": "HIGH",
        "channels": [Channel.USER, Channel.DOCUMENT]
    },
    {
        "id": "RULE_02_EXFILTRATION",
        "pattern": r"(?i)(leak|print|show|reveal)\s+.*(password|system\s+prompt|key|secret)",
        "weight": 0.75,
        "severity": "HIGH",
        "channels": [Channel.USER, Channel.DOCUMENT]
    },
    {
        "id": "RULE_03_ROLE_PLAY",
        "pattern": r"(?i)you\s+are\s+now\s+(a|an)?\s*(unrestricted|dan|jailbroken)",
        "weight": 0.90,
        "severity": "CRITICAL",
        "channels": [Channel.USER, Channel.DOCUMENT]
    }
]

class Message(BaseModel):
    role: str
    content: Union[str, List[Dict[str, Any]]]

class ChatRequest(BaseModel):
    messages: List[Message]

# 3. Noisy-OR Threat Combiner: P(Attack) = 1 - PRODUCT(1 - weight_i)
def calculate_threat_score(matched_weights: List[float]) -> float:
    if not matched_weights:
        return 0.0
    
    product = 1.0
    for w in matched_weights:
        product *= (1.0 - w)
        
    score = 1.0 - product
    return round(min(score, 0.999), 3)  # Cap below 1.0 mathematically

# 4. Scanning Logic
def scan_payload(request: ChatRequest):
    flagged_rules = []
    matched_weights = []
    
    for msg in request.messages:
        # Determine channel
        if msg.role == "system":
            channel = Channel.SYSTEM
        elif msg.role == "user":
            channel = Channel.USER
        else:
            channel = Channel.DOCUMENT
            
        content_str = str(msg.content)
        
        # System prompt is trusted and skipped
        if channel == Channel.SYSTEM:
            continue
            
        # Run rules against non-system channels
        for rule in DETECTION_RULES:
            if channel in rule["channels"]:
                if re.search(rule["pattern"], content_str):
                    flagged_rules.append({
                        "rule_id": rule["id"],
                        "severity": rule["severity"],
                        "channel": channel.value,
                        "weight": rule["weight"]
                    })
                    matched_weights.append(rule["weight"])
                    
    threat_score = calculate_threat_score(matched_weights)
    
    # Decide action based on score threshold (e.g., 0.50)
    verdict = "BLOCK" if threat_score >= 0.50 else "ALLOW"
    
    return {
        "verdict": verdict,
        "threat_score": threat_score,
        "flagged_rules": flagged_rules
    }

@app.get("/healthz")
async def health_check():
    return {"status": "ok", "message": "Aegis Firewall is alive!"}

@app.post("/v1/scan")
async def scan_endpoint(request: ChatRequest):
    return scan_payload(request)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)