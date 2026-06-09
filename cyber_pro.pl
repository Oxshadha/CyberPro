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


% --- Module 4: API Entry Point ---
% This is the main function called by Node.js via child_process.
api_diagnose :-
    catch(
        (
            threat(Threat), !, 
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
api_diagnose :-
    format('RESULT=none~n').

% Clean up the session before running a new evaluation
reset_session :-
    retractall(known(_, _)).

% Helper to assert a fact from Node.js
assert_fact(YesNo, Symptom) :-
    assertz(known(YesNo, Symptom)).
