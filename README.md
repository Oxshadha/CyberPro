# CyberPro SOC Diagnostic System

CyberPro is an advanced **Expert System** built for Security Operations Center (SOC) triage. It bridges traditional logic programming with modern web technologies, using a **Prolog Inference Engine** on the backend and a sleek, industrial-grade **Node.js Web Dashboard** on the frontend.

## 🚀 Key Features

* **Backward Chaining Inference Engine:** Built purely in SWI-Prolog, the system deduces 9 critical cyber threat scenarios by logically validating symptoms against a known rulebase.
* **Dynamic Fact Database:** Uses Prolog's `assertz` meta-predicate to dynamically build state in memory as the user interacts with the system, minimizing redundant questions.
* **Industrial Glassmorphism UI:** A premium, dark-mode "Graphite/Charcoal" dashboard built with HTML, CSS Flexbox/Grid, and Lucide SVG icons.
* **Transparent Execution:** Features a live terminal emulator that streams the raw `swipl` CLI commands and responses directly to the user to prove logical execution.
* **Mermaid.js Visual Tracing:** Every diagnosis automatically generates a flowchart showing the exact Facts → Rules → Conclusion logic path that Prolog took.

## 🧠 The 9 Threat Knowledge Base

CyberPro can successfully diagnose and provide mitigation strategies for:
1. Distributed Denial of Service (DDoS)
2. SQL Injection
3. Ransomware
4. Insider Threat
5. Reconnaissance (Port Scanning)
6. Phishing Campaigns
7. Cryptojacking Infection
8. Cloud Data Exfiltration
9. Website Defacement

## 🛠 Setup and Installation

### Prerequisites
You must have **SWI-Prolog** and **Node.js** installed on your machine.
- macOS: `brew install swi-prolog node`
- Ubuntu: `sudo apt install swi-prolog nodejs npm`
- Windows: Download binaries from their official websites.

*(Ensure the `swipl` command is available in your system PATH).*

### Running the Project

1. **Install Dependencies:**
   Navigate into the UI directory and install the required Node.js packages:
   ```bash
   cd chat-ui
   npm install
   ```

2. **Start the Application:**
   Run the Node.js Express server:
   ```bash
   npm start
   ```

3. **Open the Dashboard:**
   Open your browser and navigate to: [http://localhost:3000](http://localhost:3000)

## 📁 Repository Structure

* `cyber_pro.pl` - The core Prolog Expert System containing rules, facts, risk scores, and mitigations.
* `chat-ui/server.js` - The Node.js API that bridges the web frontend via `child_process` to the `swipl` binary.
* `chat-ui/public/` - The frontend assets (HTML, CSS, JS).
* `Explore_Cyber_pro.md` - A comprehensive Viva & Demo guide explaining the architecture, Prolog predicates, and expected Q&A.
