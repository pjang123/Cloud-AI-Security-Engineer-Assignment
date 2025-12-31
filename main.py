import os
import argparse
import json
import time
import re
from typing import List, Optional, Set
from dotenv import load_dotenv

# Import all supported SDKs
from google import genai
from openai import OpenAI
import anthropic

# Load API key
load_dotenv()

# --- SECURITY UTILS ---
def sanitize_filename(filename: str) -> str:
    """
    SECURITY CONTROLS: Input Validation
    Prevents Path Traversal attacks (e.g., '../../etc/passwd') by stripping 
    dangerous characters and directory separators from output filenames.
    """
    # Remove directory separators and null bytes
    safe_name = os.path.basename(filename)
    # Allow only alphanumeric, dashes, underscores, and dots
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '', safe_name)
    if not safe_name:
        safe_name = "unnamed_report.txt"
    return safe_name

# --- CLI SETUP ---
def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI Security Analyst Assistant (Purple Team Tool)")
    
    # Input Modes
    parser.add_argument("logfiles", nargs='*', help="List of log files")
    parser.add_argument("--folder", "-f", help="Scan entire folder")
    parser.add_argument("--watch", help="Sentinel Mode (Watch folder)")
    
    # Configuration
    parser.add_argument("--key", help="Manually provide API key (overrides .env)")
    parser.add_argument("--threshold", type=int, default=1, help="Sentinel threshold")
    parser.add_argument("--output", "-o", help="Name of the report file (Saved in /reports)")
    parser.add_argument("--lines", type=int, default=0, help="Smart Truncation lines")
    parser.add_argument("--context", "-c", help="System Context")
    
    return parser.parse_args()

# --- CORE LOGIC ---
def detect_provider(api_key: str) -> str:
    """Identifies the AI provider based on key prefix pattern matching."""
    if api_key.startswith("AIza"):
        return "google"
    elif api_key.startswith("sk-ant"):
        return "anthropic"
    elif api_key.startswith("sk-"):
        return "openai"
    else:
        return "unknown"

def read_single_file(filepath: str, line_limit: int = 0) -> str:
    """Reads a file safely with error handling and smart truncation."""
    if not os.path.exists(filepath): return ""
    
    try:
        content = ""
        # Handle JSON (Structured Data)
        if filepath.lower().endswith('.json'):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = json.dumps(json.load(f), indent=2) 
        # Handle Text (Unstructured Data)
        else:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # Data Minimization: Only process what is needed
                if line_limit > 0 and len(lines) > line_limit:
                    content = "".join(lines[-line_limit:])
                else:
                    content = "".join(lines)
        return f"\n--- FILE: {filepath} ---\n{content}\n"
    except Exception as e:
        print(f"⚠️ Warning: Could not read {filepath}: {e}")
        return ""

def analyze_with_ai(log_data: str, api_key: str, context: Optional[str] = None) -> str:
    """Dispatches the analysis request to the appropriate vendor SDK."""
    provider = detect_provider(api_key)
    
    system_prompt = (
        "You are a Tier 3 Security Analyst. Analyze these logs for threats.\n"
        "STRICT PLAIN TEXT FORMAT (NO MARKDOWN):\n"
        "- UPPERCASE HEADERS\n"
        "- Hyphen bullet points\n"
        "- Timestamps: DATE: YYYY-MM-DD, TIME: HH:MM:SS UTC\n"
        "REPORT SECTIONS: 1. EXECUTIVE SUMMARY, 2. ANALYSIS, 3. REMEDIATION"
    )
    if context: system_prompt += f"\nCONTEXT: {context}"
    
    full_user_prompt = f"LOG DATA:\n{log_data}"

    try:
        if provider == "google":
            print("🤖 Using Engine: Google Gemini 2.5 Flash")
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model="gemini-2.5-flash", 
                contents=system_prompt + "\n\n" + full_user_prompt
            )
            return response.text

        elif provider == "openai":
            print("🤖 Using Engine: OpenAI GPT-4o")
            client = OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": full_user_prompt}
                ]
            )
            return response.choices[0].message.content

        elif provider == "anthropic":
            print("🤖 Using Engine: Claude 3.5 Sonnet")
            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": full_user_prompt}]
            )
            return response.content[0].text

        else:
            return "❌ Error: Invalid API Key format."

    except Exception as e:
        return f"❌ API Error: {e}"

def save_report(report_content: str, filename: str):
    """Saves the report to the reports/ directory using sanitized paths."""
    output_dir = "reports"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Security: Prevent Directory Traversal
    safe_filename = sanitize_filename(filename)
    full_path = os.path.join(output_dir, safe_filename)

    with open(full_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
        print(f"\n✅ Report saved to: {full_path}")

def process_batch(files: List[str], args: argparse.Namespace, api_key: str):
    """Aggregates multiple log files into a single context window."""
    data = ""
    print(f"\n🔍 Reading {len(files)} files...")
    for f in files: data += read_single_file(f, args.lines)
    
    if not data.strip(): return
    
    report = analyze_with_ai(data, api_key, args.context)
    
    print("\n" + "="*40 + "\nFINAL SECURITY REPORT\n" + "="*40 + "\n" + report)
    
    if args.output:
        outfile = args.output
        if args.watch: 
            outfile = f"{outfile.split('.txt')[0]}_{int(time.time())}.txt"
        save_report(report, outfile)

# --- MAIN EXECUTION ---
def main():
    args = get_args()
    
    # Priority: CLI -> Env Var -> None
    api_key = args.key if args.key else os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    
    if not api_key:
        print("❌ Error: No API Key found.")
        return

    files = []
    if args.watch:
        print(f"👀 Watching {args.watch}...")
        seen: Set[str] = set(os.listdir(args.watch))
        pending: List[str] = []
        
        try:
            while True:
                current = set(os.listdir(args.watch))
                new_files = current - seen
                for f in new_files:
                    path = os.path.join(args.watch, f)
                    if os.path.isfile(path):
                        print(f"✨ Detected: {f}")
                        pending.append(path)
                        seen.add(f)
                
                if len(pending) >= args.threshold:
                    process_batch(pending, args, api_key)
                    pending = []
                time.sleep(3)
        except KeyboardInterrupt:
            print("\n🛑 Sentinel Mode Deactivated.")
    
    elif args.folder:
        files = [os.path.join(args.folder, f) for f in os.listdir(args.folder) if os.path.isfile(os.path.join(args.folder, f))]
        process_batch(files, args, api_key)
        
    elif args.logfiles:
        process_batch(args.logfiles, args, api_key)

if __name__ == "__main__":
    main()