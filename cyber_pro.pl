% ====================================================================
% CyberPro - SOC Alert Triage Expert System
% ====================================================================

% --- Module 1: Knowledge Base (Data objects & Structures) ---
% alert_weight(EventName, Weight)
alert_weight(port_scan, 2).
alert_weight(sql_injection_attempt, 4).
alert_weight(suspicious_login, 3).
alert_weight(malware_signature, 5).
alert_weight(data_exfiltration, 5).
alert_weight(privilege_escalation, 4).
alert_weight(unauthorized_access, 4).
alert_weight(service_unavailable, 4).
alert_weight(high_network_traffic, 3).

% threat(ThreatName, ThreatLevel)
threat(reconnaissance, low).
threat(sql_injection, high).
threat(ddos, high).
threat(insider_threat, critical).
threat(apt_breach, critical).

% mitigation(ThreatName, Strategy)
mitigation(reconnaissance, 'Block IP at firewall and monitor.').
mitigation(sql_injection, 'Patch database input validation and run WAF.').
mitigation(ddos, 'Use rate limiting, traffic filtering, and contact ISP.').
mitigation(insider_threat, 'Revoke user credentials immediately and audit logs.').
mitigation(apt_breach, 'Isolate network segments, initiate incident response.').


% --- Module 2: State Management (Dynamic DB: assertz, retract) ---
:- dynamic active_alert/1.
active_alert(empty). % dummy start

% Initialize/clear DB
clear_alerts :-
    retractall(active_alert(_)).

% Add alert dynamically
add_alert(Event) :-
    assertz(active_alert(Event)).


% --- Module 3: List Utilities (Lists, length, membership, concatenation, deleting) ---
% Get all current alerts into a list using bagof
get_all_alerts(List) :-
    bagof(E, active_alert(E), List), !.
get_all_alerts([]).

% Concatenate two lists (e.g., firewall logs + endpoint logs)
combine_logs(List1, List2, Combined) :-
    append(List1, List2, Combined).

% Delete false positives (e.g., ignoring harmless port scans for risk scoring)
filter_false_positives([], []).
filter_false_positives(RawList, Filtered) :-
    delete(RawList, port_scan, Filtered).

% Count items
count_alerts(List, N) :-
    length(List, N).

% List Membership
is_valid_event(Event) :-
    ValidEvents = [port_scan, sql_injection_attempt, suspicious_login, malware_signature, data_exfiltration, privilege_escalation, unauthorized_access, service_unavailable, high_network_traffic],
    member(Event, ValidEvents).


% --- Module 4: Inference Engine (Rules, Cut, Negation as Failure) ---
% Check if an event exists in DB
has_event(Event) :-
    active_alert(Event).

% Threat definitions
detect_threat(reconnaissance) :-
    has_event(port_scan),
    \+ has_event(blocked_by_firewall). % Negation as failure

detect_threat(sql_injection) :-
    has_event(sql_injection_attempt),
    \+ has_event(waf_blocked).

detect_threat(ddos) :-
    has_event(service_unavailable).

detect_threat(ddos) :-
    has_event(high_network_traffic).

detect_threat(insider_threat) :-
    has_event(suspicious_login),
    has_event(data_exfiltration), !. % Cut: definitive match, stop checking alternatives

detect_threat(apt_breach) :-
    has_event(malware_signature),
    has_event(privilege_escalation).

detect_threat(apt_breach) :-
    has_event(unauthorized_access),
    has_event(data_exfiltration).

% Primary threat identified (stops at first match using cut)
primary_threat(T) :-
    detect_threat(T), !.


% --- Module 5: Aggregation & Arithmetic (setof, is) ---
% Get unique detected threats
unique_threats(Threats) :-
    setof(T, detect_threat(T), Threats), !.
unique_threats([]).

% Calculate Risk Score based on event weights (Arithmetic)
calculate_risk([], 0).
calculate_risk([Event|Rest], TotalScore) :-
    ( alert_weight(Event, W) -> Weight = W ; Weight = 0 ),
    calculate_risk(Rest, SubTotal),
    TotalScore is SubTotal + Weight. % is/2


% --- Module 6: Meta-Programming (=.., functor, arg, call) ---
% Unpack a structured alert like sensor(firewall, port_scan)
analyze_structured_alert(StructAlert) :-
    StructAlert =.. [Functor, Sensor, Event], % =.. (univ)
    format('Analyzed ~w alert from sensor: ~w. Event: ~w~n', [Functor, Sensor, Event]),
    % dynamically build a call to check its weight
    Goal =.. [alert_weight, Event, _Weight],
    ( call(Goal) -> % call
        format('Warning: This is a known risky event.~n')
    ;
        format('Notice: Event weight unknown.~n')
    ).

% Inspect structure using functor and arg
inspect_event(EventTerm) :-
    functor(EventTerm, Name, Arity),
    format('Term Name: ~w, Arguments: ~w~n', [Name, Arity]),
    ( Arity > 0 ->
        arg(1, EventTerm, FirstArg),
        format('Primary indicator: ~w~n', [FirstArg])
    ;
        true
    ).

% Repeatedly calling a goal over a list
process_all_alerts([]).
process_all_alerts([H|T]) :-
    format('Processing event: ~w~n', [H]),
    inspect_event(event(H)), % dummy wrapper to show functor usage
    process_all_alerts(T). % Repeatedly calling (recursion)


% --- Module 7: Interactive I/O (read, write, loops) ---
% Main diagnosis interface
diagnose :-
    write('========================================='), nl,
    write(' CyberPro SOC Triage Expert System'), nl,
    write('========================================='), nl,
    clear_alerts,
    collect_alerts,
    nl, write('--- INITIATING SOC ANALYSIS ---'), nl,
    get_all_alerts(RawList),
    
    % Demonstrate list deletion (Filtering false positive port scans)
    filter_false_positives(RawList, FilteredList),
    count_alerts(FilteredList, N),
    format('Total actionable alerts to analyze: ~w~n', [N]),
    
    % Repeated call / Meta programming demo
    process_all_alerts(FilteredList),
    nl,
    
    % Arithmetic Risk Score
    calculate_risk(FilteredList, Score),
    format('>> Calculated Network Risk Score: ~w <<~n~n', [Score]),
    
    % Aggregation & Inference
    unique_threats(Threats),
    report_threats(Threats).

% Recursive I/O loop
collect_alerts :-
    write('Enter security event (e.g., port_scan. or sql_injection_attempt.). Type done. to finish: '), nl,
    read(Input),
    ( Input = done ->
        write('Data collection complete.'), nl
    ;
        ( is_valid_event(Input) ->
            add_alert(Input)
        ;
            write('Unknown event. Recorded as generic anomaly.'), nl,
            add_alert(Input)
        ),
        collect_alerts
    ).

% Reporting loop
report_threats([]) :-
    write('No critical threats detected based on actionable alerts.'), nl.
report_threats([T|Rest]) :-
    threat(T, Level),
    mitigation(T, Mit),
    write('! THREAT DETECTED !'), nl,
    format('Type: ~w~n', [T]),
    format('Severity: ~w~n', [Level]),
    format('Action Required: ~w~n~n', [Mit]),
    report_threats(Rest).
