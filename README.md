# Deriv-AI-Hackathon
AI Security Suite combining an AI WAF and AI Pentester. Protects LLM apps from prompt injections, detects zero-day vulnerabilities, and automates security testing — ensuring AI applications are safe, reliable, and ready for real-world deployment.

AI Security Suite combining an AI WAF and AI Pentester. Protects LLM apps from prompt injections, detects vulnerabilities, and automates security testing for safer LLM applications.

## Quick Start

### 1) Create a virtual environment (recommended)
```bash
python -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies
```bash
pip install -r requirements.txt
```

### 3) Run component smoke tests
```bash
python test_components.py
```

### 4) Launch Streamlit UI
```bash
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```

## Which URL should I open?

If Streamlit is started with `--server.address 0.0.0.0`, **do not** open `http://0.0.0.0:8501` directly in your browser.

Use one of these instead:
- `http://localhost:8501/`
- `http://127.0.0.1:8501/`

No extra path is required (you do **not** need `/something` after the port).

### Why `0.0.0.0` fails in browser
`0.0.0.0` is a bind address for the server process, not a routable client destination. Browsers may show `ERR_ADDRESS_INVALID` if you try to navigate to it.

## Cloud/dev-container note
If you're running inside Docker, Codespaces, or a remote VM, open the **forwarded/public URL** provided by that environment instead of localhost.

## Features

- **AI WAF**
  - Prompt injection and jailbreak detection (`input_filter.py`)
  - Sensitive output redaction (`output_filter.py`)
  - Session risk/anomaly tracking (`behavior_monitor.py`)

- **Autonomous Pentester**
  - Attack payload generation (`attack_generator.py`)
  - Vulnerability scoring (`vulnerability_analyzer.py`)
  - Markdown/HTML report generation (`report_generator.py`)

- **Core LLM Pipeline**
  - Security-layer orchestration (`llm_pipeline.py`)
  - Optional retrieval augmentation (`rag_engine.py`)

- **Streamlit Dashboard**
  - Secure Chat
  - Pentest Mode
  - Logs Dashboard
