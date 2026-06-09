const express = require('express');
const { exec } = require('child_process');

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.static('public'));

const currentSession = {
    knownFacts: [],
    targetThreat: null,
    currentQuestion: null
};

const PROLOG_ATOMS = new Set([
    'ddos',
    'sql_injection',
    'ransomware',
    'insider_threat',
    'reconnaissance',
    'phishing_campaign',
    'cryptojacking_infection',
    'cloud_data_breach',
    'website_defacement',
    'service_unavailable',
    'high_network_traffic',
    'many_source_ips',
    'traffic_recovers_when_filtered',
    'database_errors',
    'sql_patterns_in_requests',
    'unauthorized_access',
    'unexpected_database_changes',
    'files_encrypted',
    'ransom_note',
    'unusual_file_extensions',
    'rapid_file_modification',
    'unusual_login_times',
    'data_exfiltration',
    'unusual_sensitive_file_access',
    'use_of_personal_storage',
    'port_scan',
    'multiple_failed_logins',
    'many_ports_targeted',
    'repeated_requests_from_same_source',
    'suspicious_emails_reported',
    'malicious_attachments_downloaded',
    'lookalike_sender_domains',
    'credentials_entered_after_email',
    'high_cpu_usage',
    'unusual_outbound_connections',
    'unknown_mining_process',
    'cpu_high_when_idle',
    'spike_outbound_traffic',
    'traffic_to_external_cloud',
    'compromised_cloud_credentials',
    'unusual_bulk_downloads',
    'homepage_changed',
    'admin_login_bypass',
    'unknown_files_on_web_server',
    'cms_files_modified'
]);

function resetSession() {
    currentSession.knownFacts = [];
    currentSession.targetThreat = null;
    currentSession.currentQuestion = null;
}

function isKnownAtom(value) {
    return PROLOG_ATOMS.has(value);
}

function parseOutput(output) {
    const result = {
        actions: [],
        trace: []
    };

    for (const line of output.split('\n')) {
        const separator = line.indexOf('=');
        if (separator === -1) continue;

        const key = line.slice(0, separator);
        const value = line.slice(separator + 1);

        if (key === 'ACTION') {
            const [number, text] = value.split('|');
            result.actions.push({ number: Number(number), text });
        } else if (key === 'TRACE') {
            const [symptom, answer, weight] = value.split('|');
            result.trace.push({ symptom, answer, weight: Number(weight) });
        } else {
            result[key.toLowerCase()] = value;
        }
    }

    return result;
}

function formatName(value) {
    return value.replace(/_/g, ' ').toUpperCase();
}

function formatEvidence(value) {
    return value.replace(/_/g, ' ');
}

function buildTraceDiagram(threat, trace) {
    const lines = ['flowchart LR'];

    trace.forEach((fact, index) => {
        const factId = `f${index + 1}`;
        const ruleId = `r${index + 1}`;
        const answer = fact.answer.toUpperCase();
        lines.push(`  ${factId}["${formatEvidence(fact.symptom)}: ${answer} (${fact.weight}%)"] --> ${ruleId}["Prolog checked known(${fact.answer}, ${fact.symptom})"]`);

        if (fact.answer === 'yes') {
            lines.push(`  ${ruleId} --> score["Evidence score for ${threat}"]`);
        } else {
            lines.push(`  ${ruleId} -. rejected .-> score`);
        }
    });

    lines.push(`  score --> conclusion{"Assessment: ${formatName(threat)}"}`);
    return lines.join('\n');
}

function buildFoundReply(data) {
    const actions = data.actions
        .sort((a, b) => a.number - b.number)
        .map(action => `${action.number}. **${action.text}**`)
        .join('\n');

    return `## Evidence-Supported Assessment: ${formatName(data.threat)}

${data.explanation}

**Confirmed indicators:** ${data.confirmed}/${data.total}

**Evidence confidence:** ${data.confidence}%

**Calculated risk:** ${data.risk}/10

**Threat impact if confirmed:** ${data.impact}/10

### Immediate Actions
${actions}

**What not to do:** ${data.avoid}

### Actual Prolog Inference Trace
\`\`\`mermaid
${buildTraceDiagram(data.threat, data.trace)}
\`\`\`
`;
}

function buildInsufficientReply(data) {
    return `## Insufficient Evidence: ${formatName(data.threat)}

The consultation completed, but the confirmed evidence did not reach the 60% threshold required for an evidence-supported assessment.

**Confirmed indicators:** ${data.confirmed}/${data.total}

**Evidence confidence:** ${data.confidence}%

**Calculated current risk:** ${data.risk}/10

### Actual Prolog Evidence Trace
\`\`\`mermaid
${buildTraceDiagram(data.threat, data.trace)}
\`\`\`

Continue monitoring and collect stronger technical evidence before treating this as a confirmed incident.`;
}

app.post('/api/chat', (req, res) => {
    const action = req.body.action || 'chat';
    const userMessage = String(req.body.message || '').toLowerCase().trim();

    if (action === 'reset') {
        resetSession();
        return res.json({ reply: 'Session reset.' });
    }

    if (action === 'answer' && currentSession.currentQuestion) {
        const answer = userMessage === 'yes' ? 'yes' : 'no';
        currentSession.knownFacts.push({
            yesNo: answer,
            symptom: currentSession.currentQuestion
        });
        currentSession.currentQuestion = null;
    } else if (action === 'initial_symptom') {
        resetSession();
        currentSession.knownFacts.push({
            yesNo: 'yes',
            symptom: userMessage
        });
    }

    const selected = currentSession.targetThreat || userMessage;

    if (!isKnownAtom(selected) || currentSession.knownFacts.some(fact => !isKnownAtom(fact.symptom))) {
        resetSession();
        return res.status(400).json({
            reply: 'The selected observation is not recognized by the knowledge base.'
        });
    }

    let assertions = currentSession.knownFacts
        .map(fact => `assert_fact(${fact.yesNo}, ${fact.symptom})`)
        .join(', ');

    if (!assertions) assertions = 'true';

    const query = `reset_session, ${assertions}, api_diagnose(${selected}).`;
    const swiplCommand = `PATH=$PATH:/Applications/SWI-Prolog.app/Contents/MacOS swipl -q -s ../cyber_pro.pl -g "${query}" -t halt`;

    exec(swiplCommand, (error, stdout) => {
        if (error) {
            console.error(error);
            return res.status(500).json({
                reply: 'Error communicating with the Prolog inference engine.'
            });
        }

        const output = stdout.trim();
        const data = parseOutput(output);
        const terminalOutput = {
            command: swiplCommand,
            output
        };

        if (data.target) currentSession.targetThreat = data.target;

        if (data.result === 'ask') {
            currentSession.currentQuestion = data.symptom;
            return res.json({
                terminalOutput,
                reply: data.question,
                isAsking: true
            });
        }

        if (data.result === 'found') {
            const reply = buildFoundReply(data);
            resetSession();
            return res.json({ terminalOutput, reply });
        }

        if (data.result === 'insufficient') {
            const reply = buildInsufficientReply(data);
            resetSession();
            return res.json({ terminalOutput, reply });
        }

        resetSession();
        return res.status(400).json({
            terminalOutput,
            reply: 'The selected observation is not recognized by the knowledge base.'
        });
    });
});

app.listen(port, () => {
    console.log(`CyberPro Dashboard UI running at http://localhost:${port}`);
});
