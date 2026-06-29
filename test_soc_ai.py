import os
from dotenv import load_dotenv
from pydantic import BaseModel
from google import genai
from google.genai import types

# 1. Force override any system/terminal caching using override=True
load_dotenv(override=True)

# 2. Grab the key cleanly from your .env file
api_key = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=api_key)

class IncidentAnalysis(BaseModel):
    threat_type: str
    severity: str
    explanation: str
    actionable_steps: list[str]

system_instruction = (
    "You are an expert Tier-2 SOC Analyst. Analyze the raw log data provided by the user. "
    "Identify the attack vector, evaluate severity, write a clear summary for a human analyst, "
    "and outline precise remediation steps."
)

def analyze_security_log(raw_log_data: str) -> str:
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=f"Analyze this log:\n{raw_log_data}",
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=IncidentAnalysis,
            temperature=0.1,
        ),
    )
    return response.text

if __name__ == "__main__":
    mock_log = """
    2026-06-24 14:32:10 UTC - Src_IP: 198.51.100.42 - Dst_IP: 10.0.0.15 - Protocol: SSH - Event: Failed Password
    2026-06-24 14:32:12 UTC - Src_IP: 198.51.100.42 - Dst_IP: 10.0.0.15 - Protocol: SSH - Event: Failed Password
    """
    print("Testing clean softcoded setup...")
    print(analyze_security_log(mock_log))