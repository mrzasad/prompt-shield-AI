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
  



<img width="1461" height="658" alt="Screenshot 2026-05-18 213944" src="https://github.com/user-attachments/assets/8e9b504c-304d-4356-84e8-b9417b0a797c" />
<img width="1798" height="668" alt="Screenshot 2026-05-18 212731" src="https://github.com/user-attachments/assets/da10ba8f-0afe-4943-a9a3-30455f8cd550" />
<img width="1427" height="851" alt="Screenshot 2026-05-18 214303" src="https://github.com/user-attachments/assets/2608288a-09d3-4e99-8293-65a4be6e3f4b" />
<img width="1483" height="825" alt="Screenshot 2026-05-18 214239" src="https://github.com/user-attachments/assets/e5853b29-5537-4885-a0d5-73be15dfbb6e" />


