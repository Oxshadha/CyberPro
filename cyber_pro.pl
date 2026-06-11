% ====================================================================
% CyberPro - SOC Alert Triage Expert System
% Uses basic Prolog lists, recursion, arithmetic, cuts and dynamic facts.
% ====================================================================

:- dynamic known/2.

:- ensure_loaded('cyber_pro_knowledge.pl').

% Locate the threat that contains the observation selected by the user.
focus_threat(Symptom, Threat) :-
    threat_profile(Threat, _, Indicators),
    member(indicator(Symptom, _), Indicators), !.

resolve_threat(Threat, Threat) :-
    threat_profile(Threat, _, _), !.
resolve_threat(Symptom, Threat) :-
    focus_threat(Symptom, Threat).

% Ask only about indicators belonging to the selected threat.
consult([]).
consult([indicator(Symptom, _)|Rest]) :-
    known(_, Symptom), !,
    consult(Rest).
consult([indicator(Symptom, _)|_]) :-
    question(Symptom, Text),
    throw(ask_user(Symptom, Text)).

% Add weights of confirmed indicators using recursion and arithmetic.
evidence_points([], 0, 0).
evidence_points([indicator(Symptom, Weight)|Rest], Points, Confirmed) :-
    known(yes, Symptom), !,
    evidence_points(Rest, RestPoints, RestConfirmed),
    Points is RestPoints + Weight,
    Confirmed is RestConfirmed + 1.
evidence_points([_|Rest], Points, Confirmed) :-
    evidence_points(Rest, Points, Confirmed).

% Risk combines the threat impact with the percentage of confirmed evidence.
calculate_scores(Impact, Indicators, Confidence, Risk, Confirmed, Total) :-
    evidence_points(Indicators, EvidencePoints, Confirmed),
    length(Indicators, Total),
    Confidence is EvidencePoints,
    Risk is (Impact * Confidence + 50) // 100.

diagnosis_status(Confidence, Confirmed, found) :-
    Confidence >= 60,
    Confirmed >= 3, !.
diagnosis_status(_, _, insufficient).

% Build and execute bagof/3 or setof/3 dynamically.
% This makes one reusable collector for different knowledge queries.
collect_knowledge(Collector, Template, Goal, Results) :-
    CollectionGoal =.. [Collector, Template, Goal, Results],
    call(CollectionGoal).

ordered_actions(Threat, Actions) :-
    collect_knowledge(
        bagof,
        Number-Text-Detail,
        (action(Threat, Number, Text), action_detail(Threat, Number, Detail)),
        Actions
    ).

profile_category(Indicators, Category) :-
    member(indicator(Symptom, _), Indicators),
    indicator_category(Symptom, Category).

evidence_categories(Indicators, Categories) :-
    collect_knowledge(
        setof,
        Category,
        profile_category(Indicators, Category),
        Categories
    ).

print_actions(Threat) :-
    ordered_actions(Threat, Actions),
    print_action_list(Actions).

print_action_list([]).
print_action_list([Number-Text-Detail|Rest]) :-
    format('ACTION=~w|~w~n', [Number, Text]),
    format('ACTION_DETAIL=~w|~w~n', [Number, Detail]),
    print_action_list(Rest).

print_categories(Indicators) :-
    evidence_categories(Indicators, Categories),
    print_category_list(Categories).

print_category_list([]).
print_category_list([Category|Rest]) :-
    format('CATEGORY=~w~n', [Category]),
    print_category_list(Rest).

print_trace([]).
print_trace([indicator(Symptom, Weight)|Rest]) :-
    known(Answer, Symptom),
    format('TRACE=~w|~w|~w~n', [Symptom, Answer, Weight]),
    print_trace(Rest).

print_result(Threat, Impact, Indicators) :-
    calculate_scores(Impact, Indicators, Confidence, Risk, Confirmed, Total),
    diagnosis_status(Confidence, Confirmed, Status),
    explanation(Threat, Explanation),
    avoid(Threat, Avoid),
    format('RESULT=~w~n', [Status]),
    format('TARGET=~w~n', [Threat]),
    format('THREAT=~w~n', [Threat]),
    format('CONFIDENCE=~w~n', [Confidence]),
    format('RISK=~w~n', [Risk]),
    format('IMPACT=~w~n', [Impact]),
    format('CONFIRMED=~w~n', [Confirmed]),
    format('TOTAL=~w~n', [Total]),
    format('EXPLANATION=~w~n', [Explanation]),
    print_categories(Indicators),
    print_actions(Threat),
    format('AVOID=~w~n', [Avoid]),
    print_trace(Indicators).

api_diagnose(Selected) :-
    resolve_threat(Selected, Threat),
    threat_profile(Threat, Impact, Indicators),
    catch(
        (
            consult(Indicators),
            print_result(Threat, Impact, Indicators)
        ),
        ask_user(Symptom, Text),
        (
            format('RESULT=ask~n'),
            format('TARGET=~w~n', [Threat]),
            format('SYMPTOM=~w~n', [Symptom]),
            format('QUESTION=~w~n', [Text])
        )
    ), !.
api_diagnose(_) :-
    format('RESULT=invalid~n').

reset_session :-
    retractall(known(_, _)).

assert_fact(YesNo, Symptom) :-
    retractall(known(_, Symptom)),
    assertz(known(YesNo, Symptom)).

% Standalone console mode for demonstrating the expert system in SWI-Prolog.
% repeat/0 keeps asking until the user enters yes or no.
console_diagnose(Selected) :-
    reset_session,
    resolve_threat(Selected, Threat),
    threat_profile(Threat, Impact, Indicators),
    console_consult(Indicators),
    print_result(Threat, Impact, Indicators).

console_consult([]).
console_consult([indicator(Symptom, _)|Rest]) :-
    question(Symptom, Text),
    format('~w (yes/no): ', [Text]),
    read_yes_no(Answer),
    assert_fact(Answer, Symptom),
    console_consult(Rest).

read_yes_no(Answer) :-
    repeat,
    read(Input),
    (
        member(Input, [yes, no])
    ->
        Answer = Input, !
    ;
        writeln('Please enter yes. or no.'),
        fail
    ).
