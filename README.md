# SecureGate: AI Input/Output Guardrail Layer

SecureGate is an open-source, dual-layer security gateway built to protect Large Language Models (LLMs) from malicious prompts and sensitive data exfiltration. Powered by Streamlit and Anthropic's Claude, it intercepts user inputs and model outputs in real time to enforce strict safety boundaries.

## 🏗️ Architecture & Data Flow

```text
User Input
    │
    ├─► [Layer 1] Regex Engine  ──►  30+ curated patterns
    │         Severity: CRITICAL / HIGH / MEDIUM
    │
    ├─► [Layer 2] LLM Classifier  ──►  Claude as Judge
    │         Returns: threat bool, category, confidence, reason
    │
    ▼
Combined Verdict: BLOCK | WARN | PASS
    │
    ├─► PASS  ─►  Downstream LLM (Safe system prompt)
    │                 │
    │                 ▼
    │            Output Scanned (Same 2 layers)
    │
    └─► BLOCK ─►  Request suppressed + Audit logged
```

## 🛡️ Threat Categories Covered

SecureGate evaluates traffic against specific security risks:
* **Prompt Injection:** Intentional system overrides (e.g., *"Ignore all previous instructions..."*).
* **Jailbreak:** Roleplay exploits and safety filter bypasses (e.g., DAN attacks).
* **DB/Log Exfiltration:** SQL injections and connection string leaks (e.g., `SELECT * FROM`).
* **Secret Probing:** Accidental or malicious exposure of API keys, passwords, and tokens.
* **Encoded Payloads:** Obfuscated attacks using Base64 blobs, `eval()`, or `exec()`.
* **Output Leaks:** System instruction disclosure or raw database responses in the final output.

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com
cd SecureGate
```

### 2. Install Dependencies
```bash
pip install streamlit anthropic
```

### 3. Run the Application
```bash
streamlit run security_guardrail_app.py
```

## ⚙️ How to Use

1. Launch the app in your browser (typically `http://localhost:8501`).
2. Input your **Anthropic API Key** into the secure sidebar field.
3. Navigate the four operational tabs:
   * **Dashboard / Architecture:** View real-time pipeline visualization.
   * **Threat Tester:** Validate the engine instantly using **9 preset attack payloads** (including benign baselines) to test layers in isolation.
   * **Live Sandbox:** Test your own custom prompt attacks and view the bidirectional scanning logs.
   * **Audit Logs:** Inspect suppressed blocks, classification confidence levels, and mitigation reasons.
  



<img width="1798" height="668" alt="Screenshot 2026-05-18 212731" src="https://github.com/user-attachments/assets/1ff6b6a8-c6e1-4782-b961-c0e9a87add93" />

