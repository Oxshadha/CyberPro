# CyberPro: Cybersecurity Diagnosis Expert System

CyberPro is a Prolog-based expert system designed to diagnose cybersecurity threats based on observed symptoms. It takes a list of symptoms, analyzes them using an inference engine, scores the risk, and provides actionable recommendations to mitigate the threats.

## Features

- **Interactive I/O**: Collects symptoms dynamically from the user.
- **Inference Engine**: Detects multiple types of attacks such as Brute Force, DDoS, Phishing, Ransomware, and Insider Threats.
- **Dynamic Knowledge Base**: Uses dynamic predicates (`assertz`, `retract`) to keep track of session data and observed symptoms.
- **Risk Scoring**: Calculates a dynamic risk score based on the count and severity of matched symptoms.
- **Explainability**: Includes a `why/1` predicate to explain *why* a certain threat was detected based on the provided symptoms.
- **Advanced Prolog Features**: Utilizes lists, membership checking, length, concatenation, negation as failure, cuts (`!`), meta-programming (`=..`, `call`, `functor`, `arg`), and aggregation (`bagof`, `setof`).

## Setup and Running

1. **Install SWI-Prolog** (if not already installed):
   - macOS (Homebrew): `brew install swi-prolog`
   - Linux (Ubuntu): `sudo apt install swi-prolog`
   - Windows: Download from the [SWI-Prolog website](https://www.swi-prolog.org/download/stable)

2. **Load the Knowledge Base**:
   Open a terminal and start SWI-Prolog with the project file:
   ```bash
   swipl -s cyber_pro.pl
   ```

3. **Run the Diagnostic System**:
   In the Prolog console, run the `diagnose.` command:
   ```prolog
   ?- diagnose.
   ```
   
   **Example Session:**
   ```
   ?- diagnose.
   Enter symptom (or done. to finish): 
   |: many_failed_logins.
   Recorded: many_failed_logins
   Enter symptom (or done. to finish): 
   |: account_lockouts.
   Recorded: account_lockouts
   Enter symptom (or done. to finish): 
   |: done.
   
   === DIAGNOSIS REPORT ===
   Threat   : brute_force
   Severity : medium
   Risk Score: 20
   Action   : Enable MFA and block suspicious IPs
   
   brute_force detected because: 
     - many_failed_logins
     - account_lockouts
   ```

## Key Predicates for Testing

You can also test individual modules directly in the REPL:
- `?- severity(ransomware, X).` (Knowledge base lookup)
- `?- add_symptom(high_network_traffic).` (Add a symptom manually)
- `?- attack(X).` (Check which attacks match current symptoms)
- `?- all_attacks(L).` (Get a list of all detected attacks)
- `?- risk_score(ddos, Score).` (Calculate risk score for a specific threat)
- `?- why(brute_force).` (Explain why brute force was diagnosed)
- `?- clear_session.` (Reset the current session and symptoms)
