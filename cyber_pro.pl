% ====================================================================
% CyberPro - Cybersecurity Diagnosis Expert System
% ====================================================================

% Module 1 - Knowledge Base
% ---- STATIC FACTS ----
symptom_weight(many_failed_logins, 3).
symptom_weight(account_lockouts, 2).
symptom_weight(high_network_traffic, 3).
symptom_weight(service_unavailable, 3).
symptom_weight(suspicious_email, 2).
symptom_weight(fake_login_page, 3).
symptom_weight(encrypted_files, 4).
symptom_weight(disabled_antivirus, 3).
symptom_weight(unknown_usb_detected, 2).
symptom_weight(port_scanning_detected, 3).

severity(brute_force, medium).
severity(ddos, high).
severity(phishing, medium).
severity(ransomware, critical).
severity(insider_threat, high).

impact(brute_force, credential_theft).
impact(ddos, service_disruption).
impact(phishing, credential_theft).
impact(ransomware, data_loss).

recommend(brute_force, 'Enable MFA and block suspicious IPs').
recommend(ddos, 'Use rate limiting and traffic filtering').
recommend(phishing, 'Train users and deploy email filtering').
recommend(ransomware, 'Restore from backup, isolate system').
recommend(insider_threat, 'Review access logs and revoke privileges').

% Module 2 - Symptom Input as Lists
:- dynamic observed_symptoms/1.
observed_symptoms([]).          % starts empty

% Add a symptom to the list using assertz
add_symptom(S) :-
    observed_symptoms(Old),
    ( member(S, Old) ->           % membership check
        write('Already recorded.'), nl
    ;
        append(Old, [S], New),    % concatenation
        retract(observed_symptoms(_)),
        assertz(observed_symptoms(New))
    ).

% Check if a symptom is active
has_symptom(S) :-
    observed_symptoms(List),
    member(S, List).             % list membership

% Count symptoms observed
symptom_count(N) :-
    observed_symptoms(List),
    length(List, N).             % length of list

% Module 3 - Inference Engine
attack(brute_force) :-
    has_symptom(many_failed_logins),
    has_symptom(account_lockouts).

attack(ddos) :-
    has_symptom(high_network_traffic),
    has_symptom(service_unavailable).

attack(phishing) :-
    has_symptom(suspicious_email),
    has_symptom(fake_login_page).

attack(ransomware) :-
    has_symptom(encrypted_files),
    has_symptom(disabled_antivirus).

attack(insider_threat) :-
    has_symptom(unknown_usb_detected),
    \+ has_symptom(port_scanning_detected).  % negation as failure

% Cut: once we confirm an attack, stop checking severity alternatives
primary_attack(A) :-
    attack(A), !.                            % cut

% Module 4 - Dynamic DB
:- dynamic session_log/1.

log_event(Event) :-
    assertz(session_log(Event)).         % assertz

clear_session :-
    retractall(observed_symptoms(_)),
    assertz(observed_symptoms([])),
    retractall(session_log(_)).          % retract all logs

% Module 5 - Aggregation
% Collect ALL possible attacks
all_attacks(List) :-
    bagof(X, attack(X), List).           % bagof

% Sorted unique attacks
sorted_attacks(Sorted) :-
    setof(X, attack(X), Sorted).        % setof

% Remove a known-safe threat from results
filtered_attacks(Filtered) :-
    all_attacks(List),
    delete(List, insider_threat, Filtered).  % deleting in lists

% Module 6 - Risk Scoring
% Score = number of matching symptoms × average weight
risk_score(Attack, Score) :-
    observed_symptoms(List),
    include(relevant_symptom(Attack), List, Relevant),
    length(Relevant, N),                 % length
    Score is N * 10.                     % arithmetic: is/2

relevant_symptom(brute_force, many_failed_logins).
relevant_symptom(brute_force, account_lockouts).
relevant_symptom(ddos, high_network_traffic).
relevant_symptom(ddos, service_unavailable).
relevant_symptom(phishing, suspicious_email).
relevant_symptom(phishing, fake_login_page).
relevant_symptom(ransomware, encrypted_files).
relevant_symptom(ransomware, disabled_antivirus).
relevant_symptom(insider_threat, unknown_usb_detected).

% Module 7 - Meta-Programming
% Dynamically call any check predicate by name
run_check(PredName, Arg) :-
    Goal =.. [PredName, Arg],    % =.. (univ operator): build a term
    call(Goal).                  % call/2

% Inspect a term's functor and args
describe_term(Term) :-
    Term =.. [Functor | Args],
    functor(Term, F, Arity),
    format('Functor: ~w, Arity: ~w~n', [F, Arity]),
    ( Args \= [] ->
        arg(1, Term, First),
        format('First arg: ~w~n', [First])
    ; true ).

% Repeatedly call a goal for a list of items
check_all([]).
check_all([H|T]) :-
    run_check(has_symptom, H),   % repeatedly calling
    check_all(T).

% Module 8 - Interactive I/O
% Collect symptoms interactively
collect_symptoms :-
    write('Enter symptom (or done. to finish): '), nl,
    read(Input),                         % input
    ( Input = done ->
        true
    ;
        add_symptom(Input),
        write('Recorded: '), write(Input), nl,  % output
        collect_symptoms               % recursive loop
    ).

% Repeat-based alternative loop
collect_loop :-
    repeat,                              % repeat
        write('Symptom (done. to stop): '), nl,
        read(X),
        ( X = done -> ! ; add_symptom(X), fail ).

% Module 9 - Final Report + Why Explanation
% Full diagnosis report
diagnose :-
    clear_session,
    collect_symptoms,
    nl, write('=== DIAGNOSIS REPORT ==='), nl,
    ( setof(A, attack(A), Attacks) ->
        report_all(Attacks)
    ;
        write('No matching threats detected.'), nl
    ).

report_all([]).
report_all([A|Rest]) :-
    severity(A, Sev),
    recommend(A, Rec),
    risk_score(A, Score),
    format('Threat   : ~w~n', [A]),
    format('Severity : ~w~n', [Sev]),
    format('Risk Score: ~w~n', [Score]),
    format('Action   : ~w~n', [Rec]), nl,
    why(A), nl,
    report_all(Rest).

% WHY predicate — explains reasoning
why(Attack) :-
    attack(Attack),
    format('~w detected because: ~n', [Attack]),
    observed_symptoms(List),
    include(is_evidence_for(Attack), List, Evidence),
    print_list(Evidence).

is_evidence_for(Attack, Symptom) :-
    relevant_symptom(Attack, Symptom).

print_list([]).
print_list([H|T]) :-
    format('  - ~w~n', [H]),
    print_list(T).
