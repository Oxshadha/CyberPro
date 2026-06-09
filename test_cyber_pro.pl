:- begin_tests(cyber_pro).

:- consult('cyber_pro.pl').

test(focus_ddos) :-
    focus_threat(service_unavailable, ddos).

test(focus_sql_injection) :-
    focus_threat(database_errors, sql_injection).

test(focus_ransomware) :-
    focus_threat(files_encrypted, ransomware).

test(focus_insider_threat) :-
    focus_threat(unusual_login_times, insider_threat).

test(focus_reconnaissance) :-
    focus_threat(port_scan, reconnaissance).

test(focus_phishing) :-
    focus_threat(suspicious_emails_reported, phishing_campaign).

test(focus_cryptojacking) :-
    focus_threat(high_cpu_usage, cryptojacking_infection).

test(focus_cloud_breach) :-
    focus_threat(spike_outbound_traffic, cloud_data_breach).

test(focus_defacement) :-
    focus_threat(homepage_changed, website_defacement).

test(sql_first_follow_up) :-
    reset_session,
    assert_fact(yes, database_errors),
    catch(
        consult([
            indicator(database_errors, 25),
            indicator(sql_patterns_in_requests, 30)
        ]),
        ask_user(Symptom, _),
        true
    ),
    assertion(Symptom == sql_patterns_in_requests).

test(calculated_sql_score) :-
    reset_session,
    assert_fact(yes, database_errors),
    assert_fact(yes, sql_patterns_in_requests),
    assert_fact(yes, unauthorized_access),
    assert_fact(no, unexpected_database_changes),
    threat_profile(sql_injection, Impact, Indicators),
    calculate_scores(Impact, Indicators, Confidence, Risk, Confirmed, Total),
    assertion(Confidence == 80),
    assertion(Risk == 7),
    assertion(Confirmed == 3),
    assertion(Total == 4).

test(two_indicators_are_insufficient) :-
    diagnosis_status(60, 2, insufficient).

test(three_indicators_can_confirm) :-
    diagnosis_status(60, 3, found).

test(trace_contains_actual_answers) :-
    reset_session,
    assert_fact(yes, database_errors),
    assert_fact(no, sql_patterns_in_requests),
    with_output_to(
        string(Output),
        print_trace([
            indicator(database_errors, 25),
            indicator(sql_patterns_in_requests, 30)
        ])
    ),
    once(sub_string(Output, _, _, _, 'TRACE=database_errors|yes|25')),
    once(sub_string(Output, _, _, _, 'TRACE=sql_patterns_in_requests|no|30')).

:- end_tests(cyber_pro).
