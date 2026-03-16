# 🔒 Cyvereign – Local Cyber-Security AI System

Cyvereign is a fully local AI system optimised for **cyber-security** and
**secure software development**. It runs entirely on your machine using Ollama
– no cloud API keys required.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Local LLM** | Powered by Ollama (deepseek-coder:6.7b / qwen2.5-coder:7b) |
| **RAG Knowledge Base** | ChromaDB + HuggingFace Embeddings over your own datasets |
| **Static Code Analysis** | Regex-based vulnerability scanner (Python, C/C++, JS, Go) |
| **CVE Lookup** | Real-time queries against the NIST NVD API |
| **Log Analyzer** | Detects brute-force, SQLi, RCE, and other attacks in log files |
| **Secure Code Generator** | LLM-powered generation of secure code examples |
| **LoRA Fine-Tuning** | Pipeline to fine-tune the base model on your own security data |

---

## 🖥️ Recommended Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU | 8 GB VRAM | RTX 5070 (12 GB) |
| CPU | 8-core | Ryzen 7 7800X3D |
| RAM | 16 GB | 32 GB |
| OS | Windows 11 / Linux | Windows 11 |

---

## 🚀 Quick Start

### 1. Install Ollama

Download and install Ollama from https://ollama.com/download

Then pull the default model:

```bash
ollama serve          # keep this running in the background
ollama pull deepseek-coder:6.7b
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure (optional)

```bash
cp .env.example .env
# Edit .env to change the model, embedding model, or NVD API key
```

### 4. Run the CLI

```bash
# Ask a cyber-security question
python cli.py ask "What is a buffer overflow and how is it exploited?"

# Scan a project for vulnerabilities
python cli.py scan ./my_project

# Look up a CVE
python cli.py cve CVE-2021-44228

# Analyse a log file
python cli.py logs /var/log/nginx/access.log

# Generate secure code
python cli.py generate "JWT authentication middleware" --language python

# Build the RAG knowledge base (after adding documents to datasets/)
python cli.py build-kb
```

---

## 📁 Project Structure

```
Cyvereign/
│
├── models/
│   ├── __init__.py
│   └── llm_interface.py        ← Ollama LLM client wrapper
│
├── datasets/
│   ├── cve/                    ← CVE knowledge (add .txt / .md files)
│   ├── owasp/                  ← OWASP knowledge
│   ├── pentest/                ← Penetration testing notes
│   └── security_research/      ← Security research papers
│
├── rag/
│   ├── __init__.py
│   ├── embeddings.py           ← HuggingFace sentence-transformer embeddings
│   └── vector_store.py         ← ChromaDB vector store + document ingestion
│
├── tools/
│   ├── __init__.py
│   ├── code_analyzer.py        ← Static vulnerability scanner
│   ├── cve_lookup.py           ← NIST NVD API client
│   ├── log_analyzer.py         ← Server log security analysis
│   └── secure_code_generator.py← LLM-powered secure code generation
│
├── agent/
│   ├── __init__.py
│   └── cybersec_agent.py       ← Main orchestration agent
│
├── training/
│   ├── datasets/               ← Instruction-tuning datasets (JSONL)
│   │   └── README.md
│   └── scripts/
│       └── train_lora.py       ← QLoRA fine-tuning pipeline
│
├── chroma_db/                  ← ChromaDB persistent storage (auto-created)
│
├── cli.py                      ← CLI entry point
├── requirements.txt
├── .env.example                ← Environment variable template
└── README.md
```

---

## 🔧 Programmatic API

You can also use Cyvereign directly in Python:

```python
from agent.cybersec_agent import CybersecAgent

cybersec_ai = CybersecAgent()

# Ask a question
cybersec_ai.ask("Analysiere diesen Code auf Schwachstellen")

# Scan a folder
cybersec_ai.scan("project_folder")

# Look up CVE
cybersec_ai.cve("CVE-2021-44228")

# Analyse logs
cybersec_ai.logs("/var/log/apache2/access.log")

# Generate secure code
cybersec_ai.generate_secure_code("Secure password hashing", language="python")

# Build knowledge base from datasets/
cybersec_ai.build_knowledge_base()
```

---

## 📚 Adding Knowledge to the RAG System

1. Add `.txt` or `.md` files to any of these folders:
   - `datasets/cve/`       – CVE descriptions and advisories
   - `datasets/owasp/`     – OWASP guides and cheat sheets
   - `datasets/pentest/`   – Penetration testing methodologies
   - `datasets/security_research/` – Research papers and reports

2. Rebuild the index:
   ```bash
   python cli.py build-kb
   ```

The AI will now include relevant passages as context when answering questions.

---

## 🧠 Fine-Tuning with LoRA

To adapt the model to your specific security domain:

1. Create a JSONL dataset in `training/datasets/` (see format in README there)
2. Run the training script:

```bash
python training/scripts/train_lora.py \
  --base_model "deepseek-ai/deepseek-coder-6.7b-instruct" \
  --dataset    "training/datasets/your_dataset.jsonl" \
  --output_dir "training/output/lora_adapter"
```

3. The LoRA adapter is saved to `training/output/lora_adapter/`
4. Load it with:

```python
from peft import PeftModel
model = PeftModel.from_pretrained(base_model, "training/output/lora_adapter")
```

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorised security testing only**.
Do not use it to attack systems without explicit written permission.
