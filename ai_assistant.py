import os
import logging
import datetime
from dotenv import load_dotenv
import anthropic

# Load environment variables from .env file
load_dotenv()

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Initialize the Anthropic client
client = anthropic.Anthropic(
    api_key=os.getenv("ANTHROPIC_API_KEY")
)

SYSTEM_PROMPT = """You are Recon AI, an expert cybersecurity assistant and security advisor with a friendly personality.
You analyze network security scan results and explain findings in plain English. And for EVERY finding you:
1. EXPLAIN - what is this in plain English
2. RISK - why does this matter? Who could exploit it and how?
3. FIX - exact step by step instructions to fix it.
4. VERIFY - how do they confirm the fix worked?
Structure every response clearly. Use simple language.
Never leave someone with a problem and no solution.
You are not just diagnosing - you are guiding them all the way to resolution.
Your goal is to help non-technical people understand their network security without feeling overwhelmed.
You have a light sense of humor and be funny - security doesn't have to be scary.

Always:
- Explain findings clearly without technical jargon
- Use friendly, approachable language - like a knowledgeable friend, not a corporate robot
- Rate overall risk as LOW, MEDIUM, HIGH, or CRITICAL based on the findings
- Give specific actionable recommendations in simple steps
- Add a light reassuring tone - most findings are fixable
- When appropriate, give the user a confidence boost - learning about your network security is genuinley impressive
- Occasionally be funny and use light humor, but NEVER downplay real risks
- End responses with a confidence boost and next steps.
"""

def analyze_with_ai(scan_data):
    logger.info("Sending scan data to Claude API...")
    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Please analyze these security scan results and explain what they mean in plain English:\n\n{scan_data}"
            }
        ]
    )
    return message.content[0].text

def save_report(scan_data, ai_analysis, timestamp, filename):
    logger.info(f"Saving AI report to {filename}")
    with open(filename, "w") as f:
        f.write("="*50 + "\n")
        f.write(" RECON AI - SECURITY ANALYSIS\n")
        f.write("="*50 + "\n")
        f.write(f"Date: {timestamp}\n")
        f.write("="*50 + "\n\n")
        f.write("RAW SCAN DATA:\n")
        f.write("="*50 + "\n\n")
        f.write(scan_data + "\n\n")
        f.write("="*50 + "\n")
        f.write("AI ANALYSIS:\n")
        f.write("="*50 + "\n")
        f.write(ai_analysis + "\n")

def main():
    print("\n" + "="*50)
    print(" Welcome to Recon AI Security Assistant")
    print("="*50 + "\n")
    print("Paste your scan results below.")
    print("When done press Enter twice:\n")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    scan_data = "\n".join(lines)
    if not scan_data.strip():
        print("No scan data provided. Exiting.")
        return
    timestamp = datetime.datetime.now().isoformat()
    filename = f"ai_analysis_{timestamp}.txt"
    print("\nAnalyzing with Recon AI...")
    ai_analysis = analyze_with_ai(scan_data)
    print("\n" + "="*50)
    print("RECON AI SAYS:")
    print("="*50)
    print(ai_analysis)
    save_report(scan_data, ai_analysis, timestamp, filename)
    print(f"\nFull report saved to: {filename}")
if __name__ == "__main__":
	main()