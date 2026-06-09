% ====================================================================
% CyberPro - SOC Alert Triage Expert System
% Uses basic Prolog lists, recursion, arithmetic, cuts and dynamic facts.
% ====================================================================

:- dynamic known/2.

% threat_profile(Threat, Impact, WeightedIndicators).
% Weights for each threat add up to 100.
threat_profile(ddos, 8, [
    indicator(service_unavailable, 30),
    indicator(high_network_traffic, 30),
    indicator(many_source_ips, 20),
    indicator(traffic_recovers_when_filtered, 20)
]).

threat_profile(sql_injection, 9, [
    indicator(database_errors, 25),
    indicator(sql_patterns_in_requests, 30),
    indicator(unauthorized_access, 25),
    indicator(unexpected_database_changes, 20)
]).

threat_profile(ransomware, 10, [
    indicator(files_encrypted, 30),
    indicator(ransom_note, 30),
    indicator(unusual_file_extensions, 20),
    indicator(rapid_file_modification, 20)
]).

threat_profile(insider_threat, 9, [
    indicator(unusual_login_times, 20),
    indicator(data_exfiltration, 30),
    indicator(unusual_sensitive_file_access, 25),
    indicator(use_of_personal_storage, 25)
]).

threat_profile(reconnaissance, 4, [
    indicator(port_scan, 30),
    indicator(multiple_failed_logins, 25),
    indicator(many_ports_targeted, 25),
    indicator(repeated_requests_from_same_source, 20)
]).

threat_profile(phishing_campaign, 7, [
    indicator(suspicious_emails_reported, 25),
    indicator(malicious_attachments_downloaded, 30),
    indicator(lookalike_sender_domains, 20),
    indicator(credentials_entered_after_email, 25)
]).

threat_profile(cryptojacking_infection, 6, [
    indicator(high_cpu_usage, 25),
    indicator(unusual_outbound_connections, 25),
    indicator(unknown_mining_process, 30),
    indicator(cpu_high_when_idle, 20)
]).

threat_profile(cloud_data_breach, 10, [
    indicator(spike_outbound_traffic, 25),
    indicator(traffic_to_external_cloud, 25),
    indicator(compromised_cloud_credentials, 30),
    indicator(unusual_bulk_downloads, 20)
]).

threat_profile(website_defacement, 6, [
    indicator(homepage_changed, 30),
    indicator(admin_login_bypass, 25),
    indicator(unknown_files_on_web_server, 25),
    indicator(cms_files_modified, 20)
]).

% Questions are also knowledge, so they belong in Prolog.
question(service_unavailable, 'Are you experiencing service unavailability, such as a website being offline?').
question(high_network_traffic, 'Is there an unusual spike in incoming network traffic?').
question(many_source_ips, 'Is the traffic arriving from a very large number of source IP addresses?').
question(traffic_recovers_when_filtered, 'Does the service recover when suspicious traffic is filtered or blocked?').

question(database_errors, 'Are applications showing SQL syntax errors or unexpected database failures?').
question(sql_patterns_in_requests, 'Do web logs contain SQL keywords or special characters in request parameters?').
question(unauthorized_access, 'Has unauthorized access to restricted data or accounts been detected?').
question(unexpected_database_changes, 'Are there unexpected database records, schema changes, or deleted data?').

question(files_encrypted, 'Are files unexpectedly encrypted or inaccessible?').
question(ransom_note, 'Has a ransom note or payment demand appeared?').
question(unusual_file_extensions, 'Have many files received unusual or unknown file extensions?').
question(rapid_file_modification, 'Were many files modified within a very short period?').

question(unusual_login_times, 'Are accounts being used at unusual times or from unusual locations?').
question(data_exfiltration, 'Is there evidence of large amounts of organizational data leaving the network?').
question(unusual_sensitive_file_access, 'Did the account access sensitive files outside its normal job duties?').
question(use_of_personal_storage, 'Was personal cloud storage, email, or removable media used to transfer data?').

question(port_scan, 'Is the firewall recording repeated connection attempts across ports?').
question(multiple_failed_logins, 'Is there a high number of failed login attempts?').
question(many_ports_targeted, 'Were many different ports or services targeted in sequence?').
question(repeated_requests_from_same_source, 'Did repeated probing requests come from the same source or subnet?').

question(suspicious_emails_reported, 'Are multiple users reporting similar suspicious emails?').
question(malicious_attachments_downloaded, 'Did users download unexpected attachments or follow suspicious links?').
question(lookalike_sender_domains, 'Do the messages use spoofed or lookalike sender domains?').
question(credentials_entered_after_email, 'Did any user enter credentials after following a link in the email?').

question(high_cpu_usage, 'Are servers or workstations showing unusually high CPU usage?').
question(unusual_outbound_connections, 'Are affected systems connecting to unknown external IP addresses or mining pools?').
question(unknown_mining_process, 'Is an unknown process consuming CPU and behaving like cryptocurrency-mining software?').
question(cpu_high_when_idle, 'Does CPU usage remain high even when the system should be idle?').

question(spike_outbound_traffic, 'Is there a sudden large spike in outbound network traffic?').
question(traffic_to_external_cloud, 'Is that traffic going to an unexpected external cloud-storage provider?').
question(compromised_cloud_credentials, 'Is there evidence that a cloud API key or privileged cloud account was compromised?').
question(unusual_bulk_downloads, 'Do audit logs show unusual bulk downloads or exports of sensitive data?').

question(homepage_changed, 'Has the public website been changed without authorization?').
question(admin_login_bypass, 'Are there suspicious successful logins to the CMS administration area?').
question(unknown_files_on_web_server, 'Were unknown scripts, pages, or backdoor files added to the web server?').
question(cms_files_modified, 'Do file-integrity logs show unauthorized changes to CMS or website files?').

explanation(ddos, 'The confirmed evidence indicates traffic-based service disruption consistent with a distributed denial-of-service attack.').
explanation(sql_injection, 'The confirmed database and request evidence indicates that crafted SQL input may have reached the application database.').
explanation(ransomware, 'The confirmed file-system evidence indicates automated encryption activity consistent with ransomware.').
explanation(insider_threat, 'The confirmed account and data-transfer evidence indicates possible misuse by an employee or a compromised internal account.').
explanation(reconnaissance, 'The confirmed connection evidence indicates systematic probing of exposed services and authentication points.').
explanation(phishing_campaign, 'The confirmed email and user-activity evidence indicates a coordinated phishing campaign.').
explanation(cryptojacking_infection, 'The confirmed resource and network evidence indicates unauthorized cryptocurrency-mining activity.').
explanation(cloud_data_breach, 'The confirmed cloud audit and transfer evidence indicates possible unauthorized extraction of cloud-hosted data.').
explanation(website_defacement, 'The confirmed website and server-integrity evidence indicates unauthorized modification of the public site.').

action(ddos, 1, 'Analyze firewall and router logs to identify traffic sources and patterns.').
action(ddos, 2, 'Apply rate limits and traffic-filtering rules at the network edge.').
action(ddos, 3, 'Contact the ISP or upstream provider for additional filtering support.').

action(sql_injection, 1, 'Review web access logs for malicious parameters and identify the affected endpoint.').
action(sql_injection, 2, 'Restrict or temporarily disable the vulnerable endpoint and preserve logs for investigation.').
action(sql_injection, 3, 'Replace unsafe database queries with parameterized queries and validate all input.').

action(ransomware, 1, 'Isolate affected hosts immediately to limit lateral movement and further encryption.').
action(ransomware, 2, 'Preserve the ransom note and system evidence to identify the ransomware family.').
action(ransomware, 3, 'Verify clean offline backups before beginning recovery.').

action(insider_threat, 1, 'Preserve authentication, file-access, DLP, VPN, and cloud audit logs.').
action(insider_threat, 2, 'Suspend the suspected account and invalidate active sessions when authorized.').
action(insider_threat, 3, 'Determine which data was accessed or transferred and notify the incident-response lead.').

action(reconnaissance, 1, 'Correlate firewall and authentication logs to identify probing sources.').
action(reconnaissance, 2, 'Block confirmed malicious sources and apply login rate limits.').
action(reconnaissance, 3, 'Review the external attack surface and close unnecessary exposed services.').

action(phishing_campaign, 1, 'Search for and quarantine matching messages across user mailboxes.').
action(phishing_campaign, 2, 'Reset credentials and revoke sessions for users who submitted credentials.').
action(phishing_campaign, 3, 'Isolate and scan endpoints that opened attachments or downloaded files.').

action(cryptojacking_infection, 1, 'Identify the process responsible for abnormal CPU consumption.').
action(cryptojacking_infection, 2, 'Isolate affected hosts and block confirmed mining destinations.').
action(cryptojacking_infection, 3, 'Remove the malicious process and investigate its persistence method.').

action(cloud_data_breach, 1, 'Revoke compromised credentials, API keys, and active cloud sessions.').
action(cloud_data_breach, 2, 'Restrict unauthorized outbound transfers while preserving audit evidence.').
action(cloud_data_breach, 3, 'Use cloud audit logs to determine the accounts, resources, and data involved.').

action(website_defacement, 1, 'Place the affected site in maintenance mode and preserve a forensic copy.').
action(website_defacement, 2, 'Remove unauthorized files and restore from a verified clean backup.').
action(website_defacement, 3, 'Reset CMS credentials and patch the access path used by the attacker.').

avoid(ddos, 'Do not repeatedly restart the affected servers; that does not stop incoming attack traffic.').
avoid(sql_injection, 'Do not leave the vulnerable endpoint publicly accessible while investigating it.').
avoid(ransomware, 'Do not erase affected systems before evidence and recovery requirements have been assessed.').
avoid(insider_threat, 'Do not alert the suspected user before evidence and access controls are secured.').
avoid(reconnaissance, 'Do not ignore repeated probing because it may precede an exploitation attempt.').
avoid(phishing_campaign, 'Do not redistribute the live malicious message or links as a warning.').
avoid(cryptojacking_infection, 'Do not rely only on a reboot because persistent malware may restart.').
avoid(cloud_data_breach, 'Do not destroy affected instances before forensic evidence has been preserved.').
avoid(website_defacement, 'Do not only replace the altered page; the original access method may remain active.').

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

print_actions(Threat) :-
    action(Threat, Number, Text),
    format('ACTION=~w|~w~n', [Number, Text]),
    fail.
print_actions(_).

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
