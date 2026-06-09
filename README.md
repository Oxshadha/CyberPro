# CyberPro: Advanced SOC Triage Expert System

CyberPro is a Prolog-based expert system designed to act as a Security Operations Center (SOC) Alert Triage assistant. It takes a list of raw security events (like port scans, malware signatures, or unauthorized accesses), filters out false positives, analyzes them using an inference engine, scores the network risk, and provides actionable mitigations.

## Features & Prolog Concepts Used

- **Data Objects & Structures**: Represents network events and threats.
- **Lists & Membership**: Validates events and manages dynamic event lists.
- **List Concatenation & Deletion**: Cleans raw data (filtering out known false positives like harmless port scans).
- **List Length & Arithmetic**: Counts actionable alerts and calculates a mathematical Risk Score.
- **Dynamic DB (`assertz`, `retract`)**: Maintains the active session's event log.
- **Inference Engine (`\+` Negation as Failure, `!` Cut)**: Deduzes complex attacks (e.g., concluding SQL Injection was successful *only if* it was not blocked by a WAF).
- **Aggregation (`bagof`, `setof`)**: Collects all unique vulnerabilities across the network.
- **Meta-Programming (`=..`, `functor`, `arg`, `call`)**: Dynamically unpacks structured alert formats and runs dynamic predicate checks.
- **Interactive I/O**: A recursive command-line interface that loops to accept commands and events from the SOC analyst.

## Setup and Running

1. **Install SWI-Prolog** (if not already installed):
   - macOS: `brew install swi-prolog`
   - Windows: Download from the [SWI-Prolog website](https://www.swi-prolog.org)

2. **Load the Knowledge Base**:
   Open a terminal, navigate to this folder, and start SWI-Prolog:
   ```bash
   swipl -s cyber_pro.pl
   ```

3. **Run the Diagnostic System**:
   In the Prolog console, start the triage process (do not type the `?-` prompt):
   ```prolog
   ?- diagnose.
   ```

## Using the Interactive Chat Frontend

In addition to the terminal, CyberPro includes a custom ChatGPT-like Web Interface!

1. **Start the Chat Server:**
   Open a new terminal window, navigate to the `chat-ui` folder, and start the Node.js server:
   ```bash
   cd chat-ui
   npm install
   npm start
   ```

2. **Open the Interface:**
   Open your web browser and navigate to:
   [http://localhost:3000](http://localhost:3000)

3. **Start Chatting:**
   Type a natural sentence like *"I am seeing port scans and unauthorized access."* The Node.js wrapper will parse your message, securely query the Prolog engine in the background, and provide a formatted diagnosis report.
