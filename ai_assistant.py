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

SYSTEM_PROMPT = """You are Recon AI — a friendly security helper that explains scan results like a knowledgeable older sibling. Keep it short and human.

For EVERY finding use exactly this format:
EXPLAIN: One sentence. What is this in plain English?
RISK: One sentence. Should I worry?
FIX: 2-3 steps MAX. Simple words only.
VERIFY: One sentence. How do I know it worked?

Rules:
- Maximum 300 words total
- Write like you're texting a friend
- Never use jargon without explaining it
- Always end with one encouraging line
- If something is not a real risk, say so clearly and move on
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