# CyberPro SOC Diagnostic System

CyberPro is an advanced **Expert System** built for Security Operations Center (SOC) triage. It bridges traditional logic programming with modern web technologies, using a **Prolog Inference Engine** on the backend and a sleek, industrial-grade **Node.js Web Dashboard** on the frontend.

## 🚀 Key Features

* **Focused Prolog Consultation:** The selected primary observation is mapped to the most relevant threat first, so a database symptom asks SQL-related follow-up questions instead of starting from DDoS.
* **Weighted Evidence Rules:** Each threat uses 4 indicators with evidence weights. A result requires at least 3 confirmed indicators and at least 60% confidence.
* **Calculated Risk Score:** Prolog calculates confidence and a 1-10 risk score from confirmed evidence and threat impact.
* **Dynamic Fact Database:** Uses Prolog's `assertz` and `retractall` predicates to dynamically build state in memory as the user interacts with the system.
* **Industrial Glassmorphism UI:** A premium, dark-mode "Graphite/Charcoal" dashboard built with HTML, CSS Flexbox/Grid, and Lucide SVG icons.
* **Transparent Execution:** Features a live terminal emulator that streams the raw `swipl` CLI commands and responses directly to the user to prove logical execution.
* **Actual Prolog Trace Output:** Prolog outputs the confirmed and rejected evidence facts used in the final assessment; the UI renders those facts as a Mermaid.js flowchart.

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

## Prolog Concepts Demonstrated

* `bagof/3` collects all ordered action-summary/detail records for the diagnosed threat.
* `setof/3` derives a sorted list of unique evidence domains involved in the assessment.
* `call/1` executes a dynamically constructed `bagof/3` or `setof/3` goal through the reusable `collect_knowledge/4` predicate.
* `repeat/0` validates yes/no input in the standalone `console_diagnose/1` consultation mode.
* Lists, recursion, `member/2`, arithmetic, cuts, `assertz/1`, and `retractall/1` support the main inference workflow.

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

* `cyber_pro.pl` - The core Prolog Expert System containing threat profiles, questions, explanations, actions, calculated scoring, and trace output.
* `test_cyber_pro.pl` - Prolog regression tests for threat focus, scoring, thresholds, and trace output.
* `chat-ui/server.js` - The Node.js API that bridges the web frontend via `child_process` to the `swipl` binary and formats Prolog output for the UI.
* `chat-ui/public/` - The frontend assets (HTML, CSS, JS).
* `Explore_Cyber_pro.md` - A comprehensive Viva & Demo guide explaining the architecture, Prolog predicates, and expected Q&A.
