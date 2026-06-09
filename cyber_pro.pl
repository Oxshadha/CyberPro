% ====================================================================
% CyberPro - SOC Alert Triage Expert System (Backward Chaining)
% ====================================================================

% Dynamic knowledge base to store facts provided by the user via the API
:- dynamic known/2.

% --- Module 1: Threats and Rules (Backward Chaining Inference) ---
% Prolog will attempt to prove a threat. If a verify/1 call fails,
% it naturally backtracks to the next threat rule.

threat(ddos) :-
    verify(service_unavailable),
    verify(high_network_traffic).

threat(sql_injection) :-
    verify(database_errors),
    verify(unauthorized_access).

threat(ransomware) :-
    verify(files_encrypted),
    verify(ransom_note).

threat(insider_threat) :-
    verify(unusual_login_times),
    verify(data_exfiltration).

threat(reconnaissance) :-
    verify(port_scan),
    verify(multiple_failed_logins).

% --- Module 2: Verification Engine (The Core of the Expert System) ---
% This module checks if we already know the answer. If not, it halts
% execution and asks the Node.js API to ask the user.

% If we already know the user answered 'yes' to this symptom, succeed.
verify(Symptom) :-
    known(yes, Symptom), !.

% If we already know the user answered 'no', fail immediately and backtrack.
verify(Symptom) :-
    known(no, Symptom), !, fail.

% If it is not in the database, we MUST ask the user.
% We use throw/1 to break out of the inference engine and send a request to Node.
verify(Symptom) :-
    throw(ask_user(Symptom)).


% --- Module 3: Mitigation Knowledge ---
mitigation(ddos, 'Use rate limiting, traffic filtering, and contact ISP.').
mitigation(sql_injection, 'Patch database input validation and run WAF.').
mitigation(ransomware, 'Disconnect infected machines, do not pay ransom, restore from backup.').
mitigation(insider_threat, 'Revoke user credentials immediately and audit logs.').
mitigation(reconnaissance, 'Block IP at firewall and monitor closely.').

% Risk Scoring
threat_score(ddos, 8).
threat_score(sql_injection, 9).
threat_score(ransomware, 10).
threat_score(insider_threat, 9).
threat_score(reconnaissance, 3).


% --- Module 4: Explanations (Simulating RAG with Prolog Facts) ---
explanation(ddos, 'A Distributed Denial of Service (DDoS) attack attempts to disrupt normal traffic of a targeted server by overwhelming it with a flood of Internet traffic. The presence of high network traffic combined with service unavailability is a strong indicator of this.').
explanation(sql_injection, 'SQL Injection is a code injection technique that might destroy your database. It is one of the most common web hacking techniques. The detection of database syntax errors alongside unauthorized access indicates a successful payload execution.').
explanation(ransomware, 'Ransomware is malicious software designed to block access to a computer system until a sum of money is paid. The combination of encrypted files and a ransom note is the definitive signature of this threat.').
explanation(insider_threat, 'An insider threat is a malicious threat to an organization that comes from people within the organization. Unusual login times combined with data exfiltration suggests a compromised or rogue employee account.').
explanation(reconnaissance, 'Reconnaissance is the active or passive gathering of information about a target network. A port scan coupled with multiple failed logins indicates an attacker is probing your defenses for vulnerabilities.').

% --- Module 5: API Entry Point ---
% Helper: Check if an item is NOT in a list
not_in_list(_, []) :- !.
not_in_list(X, [H|T]) :- X \= H, not_in_list(X, T).

% This is the main function called by Node.js. It accepts a list of already found threats
% to skip, allowing us to find "Alternate Answers".
api_diagnose(ExcludedThreats) :-
    catch(
        (
            threat(Threat),
            not_in_list(Threat, ExcludedThreats), !, 
            mitigation(Threat, Mit),
            threat_score(Threat, Score),
            format('RESULT=found~nTHREAT=~w~nSCORE=~w~nMITIGATION=~w~n', [Threat, Score, Mit])
        ),
        ask_user(Symptom),
        (
            format('RESULT=ask~nSYMPTOM=~w~n', [Symptom])
        )
    ).

% If no threat matches the given symptoms, and no more questions to ask:
api_diagnose(_) :-
    format('RESULT=none~n').

% Entry point for explanations
api_explain(Threat) :-
    ( explanation(Threat, Text) ->
        format('EXPLANATION=~w~n', [Text])
    ;
        format('EXPLANATION=No detailed explanation available for this threat.~n')
    ).

% Clean up the session before running a new evaluation
reset_session :-
    retractall(known(_, _)).

% Helper to assert a fact from Node.js
assert_fact(YesNo, Symptom) :-
    assertz(known(YesNo, Symptom)).
