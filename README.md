Yes, I found the "Bespin Assignment README" in your drive. Here is the content formatted as a GitHub `README.md` file.

---

# 🛡️ AI Security Analyst Assistant

**Bespin Assignment**

This tool is designed to automate the ingestion, analysis, and correlation of security artifacts. It moves beyond simple signature matching by utilizing LLMs to identify anomalous behavior, contextualize threats, and generate actionable remediation reports.

## 📋 Features

* 
**Multiple Provider Support:** Automatically detects and switches between Google Gemini, OpenAI GPT-4, and Anthropic Claude based on the API key provided.


* **Three Operational Modes:**
* **Standard:** Analyze specific files on demand.
* **Bulk Folder:** Ingest entire directories of logs for mass analysis.
* **Sentinel (Watch):** Real-time folder monitoring for continuous analysis.


* 
**Security First:** Includes input sanitization to prevent path traversal attacks and data minimization via smart truncation.


* 
**Purple Team Focused:** Generates reports that include both attack vector analysis and defensive remediation steps.



## ⚙️ Setup Instructions

### 1. Prerequisites

* Python 3.10 or higher 


* A valid API Key from Google, OpenAI, or Anthropic 



### 2. Installation

It is recommended to use a virtual environment manager like `uv` or `venv`.

```bash
# Clone the repository (if applicable) or enter directory
cd BespinAssignment

# Create virtual environment
uv venv  # or: python -m venv .venv

# Activate environment
# Windows:
.venv\Scripts\activate
# Mac/Linux:
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements.txt
# or: pip install -r requirements.txt

```

### 3. API Key Configuration

There are two options to provide an API key.

**Option A: Environment File**
Add the API key to the `.env` file in the root directory.

**Option B: Command Line**
Use the `--key` command flag at runtime.

Example:

```bash
python main.py logs/server.log --key "sk-proj-12345..."

```

## 🚀 How to Run

### Mode 1: Standard Analysis (Single/Multi File)

Best for ad-hoc analysis of specific artifacts.

```bash
python main.py logs/server_logs.txt logs/app_metrics.json --output report.txt

```

### Mode 2: Bulk Folder Scan

Ingests all files in a directory to correlate events across multiple logs.

```bash
python main.py --folder logs/ --context "Production Ubuntu Web Server"

```

### Mode 3: Sentinel Mode (Watch)

Continuously watches a folder. When new logs appear, it batches them and triggers analysis.

```bash
# Waits for 2 new files before triggering a report
python main.py --watch logs/ --threshold 2

```

## 🚩 Command Flags

| Flag | Description |
| --- | --- |
| `--output`, `-o` | Save the report to the `reports/` folder instead of printing to console. |
| `--folder`, `-f` | Bulk Mode. Scans every valid file inside a specific folder. |
| `--context`, `-c` | Inject system context (OS, role, network segment) to reduce LLM hallucinations. |
| `--lines` | Smart Truncation: Only analyze the last N lines of a file to prevent token overflow. |
| `--threshold` | Sets how many new files to wait for before triggering a scan (used with `--watch`). |
| `--key` | Manual Override. Force use of a specific API key (overrides `.env`). |
| `--watch` | Sentinel Mode. Continuously monitors a folder for new files. |

## ⚠️ Known Weaknesses & Constraints

1. **Token Limits:** While "Smart Truncation" (`--lines`) is implemented, extremely large log files (larger than 1GB) cannot be ingested in their entirety without splitting. The tool currently overcomes this by prioritizing the most recent data.


2. **Stateless Analysis:** The tool treats each batch execution as an isolated event. It does not maintain a local database of past incidents, meaning it cannot detect "Low and Slow" attacks that span weeks across different execution batches.


3. **Data Privacy:** Logs are sent to external cloud APIs (Google/OpenAI/Anthropic). This tool should not be used with logs containing PII (Personally Identifiable Information) or sensitive secrets without prior sanitization/redaction.


4. 
**Costs:** Continuous usage of "Sentinel Mode" with a low threshold (every 1 file) could incur significant API costs.



## 🔮 Future Enhancements

Improvements that could be made if there were more time available:

1. 
**Local LLM Support:** Integrate Ollama or LocalAI to allow analysis of sensitive logs entirely offline, removing data privacy concerns.


2. **RAG (Retrieval-Augmented Generation):** Implement a vector database (like ChromaDB) to store past log embeddings. This would allow the AI to reference historical anomalies and detect long-term patterns.


3. 
**SIEM Integration:** Add webhooks to forward the generated reports directly to monitoring dashboards.