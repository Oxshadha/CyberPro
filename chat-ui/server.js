const express = require('express');
const { exec } = require('child_process');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- Chat Session State ---
let currentSession = {
    knownFacts: [], 
    excludedThreats: [], 
    lastThreat: null
};
let isAsking = false;
let currentQuestion = null;

const QUESTION_MAP = {
    'service_unavailable': 'Are you experiencing service unavailability (e.g., website offline)?',
    'high_network_traffic': 'Are you noticing an unusual spike in incoming network traffic?',
    'database_errors': 'Are your applications throwing SQL syntax or database connection errors?',
    'unauthorized_access': 'Have you detected any unauthorized access to restricted systems?',
    'files_encrypted': 'Are your files unexpectedly encrypted or inaccessible?',
    'ransom_note': 'Have you found any ransom notes or payment demands?',
    'unusual_login_times': 'Are users logging in at unusual hours (e.g., 3 AM)?',
    'data_exfiltration': 'Is there evidence of large amounts of data leaving the network?',
    'port_scan': 'Is your firewall blocking repeated connection attempts to various ports?',
    'multiple_failed_logins': 'Are you seeing a high number of failed login attempts?'
};

app.post('/api/chat', (req, res) => {
    const action = req.body.action || 'chat';
    const userMessage = (req.body.message || '').toLowerCase();

    // 1. Handle Reset
    if (action === 'reset') {
        currentSession.knownFacts = [];
        currentSession.excludedThreats = [];
        currentSession.lastThreat = null;
        isAsking = false;
        currentQuestion = null;
        return res.json({ reply: 'Session reset.' });
    }

    // 2. Handle Action Area Responses (Yes/No)
    if (isAsking && action === 'answer') {
        const answer = userMessage === 'yes' ? 'yes' : 'no';
        currentSession.knownFacts.push({ yesNo: answer, symptom: currentQuestion });
        isAsking = false;
        currentQuestion = null;
    } 
    // 3. Handle Initial Symptom Selection
    else if (action === 'initial_symptom') {
        const selectedSymptom = userMessage.trim();
        if (!currentSession.knownFacts.find(f => f.symptom === selectedSymptom)) {
            currentSession.knownFacts.push({ yesNo: 'yes', symptom: selectedSymptom });
        }
    }

    let assertStatements = currentSession.knownFacts.map(f => `assert_fact(${f.yesNo}, ${f.symptom})`).join(', ');
    if (!assertStatements) assertStatements = 'true';
    
    const excludedList = `[${currentSession.excludedThreats.join(',')}]`;

    const query = `
        reset_session,
        ${assertStatements},
        api_diagnose(${excludedList}).
    `;

    const cleanQuery = query.trim().replace(/\n/g, ' ').replace(/\s+/g, ' ');
    const swiplCommand = `PATH=$PATH:/Applications/SWI-Prolog.app/Contents/MacOS swipl -s ../cyber_pro.pl -g "${cleanQuery}" -t halt`;

    exec(swiplCommand, (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            if(error.message.includes("swipl: command not found") || error.code === 127) {
                return res.json({ reply: "⚠️ **SWI-Prolog is not installed or not in PATH.**" });
            }
            return res.status(500).json({ reply: "Error communicating with the Prolog inference engine." });
        }
        
        const output = stdout.trim();
        
        // Prepare terminal output payload
        const terminalOutput = {
            command: swiplCommand,
            output: output
        };

        const lines = output.split('\n').map(l => l.trim());
        
        let resultType = '';
        let symptom = '', threat = '', score = '', mitigation = '';

        for (let i = 0; i < lines.length; i++) {
            if (lines[i] === 'RESULT=ask') resultType = 'ask';
            if (lines[i] === 'RESULT=found') resultType = 'found';
            if (lines[i] === 'RESULT=none') resultType = 'none';

            if (lines[i].startsWith('SYMPTOM=')) symptom = lines[i].split('=')[1];
            if (lines[i].startsWith('THREAT=')) threat = lines[i].split('=')[1];
            if (lines[i].startsWith('SCORE=')) score = lines[i].split('=')[1];
            if (lines[i].startsWith('MITIGATION=')) mitigation = lines[i].split('=')[1];
        }

        if (resultType === 'found') {
            const formattedThreat = threat.replace(/_/g, ' ').toUpperCase();
            
            let richMitigation = '';
            let chartRules = '';

            if (threat === 'ddos') {
                richMitigation = `1. <span style="color: #10b981;">**Analyze Traffic Patterns:**</span> Check firewall and router logs for unusual spikes from specific geographic regions or IP ranges.\n2. <span style="color: #10b981;">**Implement Rate Limiting:**</span> Apply immediate rate limiting rules on the edge routers or WAF to drop excessive packets.\n3. <span style="color: #10b981;">**Contact ISP:**</span> Notify your Internet Service Provider to upstream the traffic filtering.\n\n<br>\n<span style="color: #ef4444;"><b>What NOT to do:</b></span> Do NOT restart the servers in a panic, as this does not stop the incoming traffic and only extends downtime.`;
                chartRules = `  f1["FACT: known(yes, service_unavailable)"] --> r1["RULE: verify(service_unavailable)"]\n  r1 --> c{"CONCLUSION: threat(ddos)"}\n  f2["FACT: known(yes, high_network_traffic)"] --> r2["RULE: verify(high_network_traffic)"]\n  r2 --> c`;
            } else if (threat === 'sql_injection') {
                richMitigation = `1. <span style="color: #10b981;">**Review Web Logs:**</span> Check HTTP access logs for unusual URL parameters containing SQL commands.\n2. <span style="color: #10b981;">**Audit Database Logs:**</span> Inspect database transaction logs to identify which tables were accessed or exfiltrated.\n3. <span style="color: #10b981;">**Patch Vulnerable Endpoints:**</span> Identify the exact API endpoint that allowed the injection and apply parameterized queries immediately.\n\n<br>\n<span style="color: #ef4444;"><b>What NOT to do:</b></span> Do NOT leave the vulnerable application online while investigating; take it offline or route it through a strict WAF immediately.`;
                chartRules = `  f1["FACT: known(yes, database_errors)"] --> r1["RULE: verify(database_errors)"]\n  r1 --> c{"CONCLUSION: threat(sql_injection)"}\n  f2["FACT: known(yes, unauthorized_access)"] --> r2["RULE: verify(unauthorized_access)"]\n  r2 --> c`;
            } else if (threat === 'ransomware') {
                richMitigation = `1. <span style="color: #10b981;">**Isolate Infected Hosts:**</span> Immediately disconnect the infected machines from the network to prevent lateral movement.\n2. <span style="color: #10b981;">**Identify the Variant:**</span> Check the ransom note for specific email addresses or extensions to identify the ransomware family.\n3. <span style="color: #10b981;">**Secure Backups:**</span> Verify that your offline or immutable backups are safe and have not been compromised.\n\n<br>\n<span style="color: #ef4444;"><b>What NOT to do:</b></span> Do NOT pay the ransom! Paying does not guarantee data recovery and funds criminal organizations.`;
                chartRules = `  f1["FACT: known(yes, files_encrypted)"] --> r1["RULE: verify(files_encrypted)"]\n  r1 --> c{"CONCLUSION: threat(ransomware)"}\n  f2["FACT: known(yes, ransom_note)"] --> r2["RULE: verify(ransom_note)"]\n  r2 --> c`;
            } else if (threat === 'insider_threat') {
                richMitigation = `1. <span style="color: #10b981;">**Audit Account Activity:**</span> Review the compromised user's active directory and VPN logs to see what files they recently accessed.\n2. <span style="color: #10b981;">**Revoke Access:**</span> Immediately suspend the user's accounts, invalidate active sessions, and rotate all shared credentials.\n3. <span style="color: #10b981;">**Check Exfiltration Points:**</span> Inspect DLP logs, USB access logs, and outbound cloud storage traffic to determine what was stolen.\n\n<br>\n<span style="color: #ef4444;"><b>What NOT to do:</b></span> Do NOT alert the suspected user prematurely before securing the logs and evidence, as they may attempt to destroy audit trails.`;
                chartRules = `  f1["FACT: known(yes, unusual_login_times)"] --> r1["RULE: verify(unusual_login_times)"]\n  r1 --> c{"CONCLUSION: threat(insider_threat)"}\n  f2["FACT: known(yes, data_exfiltration)"] --> r2["RULE: verify(data_exfiltration)"]\n  r2 --> c`;
            } else if (threat === 'reconnaissance') {
                richMitigation = `1. <span style="color: #10b981;">**Correlate IP Addresses:**</span> Check firewall logs to identify the source IP addresses conducting the port scans and failed logins.\n2. <span style="color: #10b981;">**Block Source IPs:**</span> Add the offending IP addresses or subnets to the firewall's strict drop list.\n3. <span style="color: #10b981;">**Review External Footprint:**</span> Ensure no unnecessary ports (like RDP/3389 or SSH/22) are exposed to the public internet.\n\n<br>\n<span style="color: #ef4444;"><b>What NOT to do:</b></span> Do NOT ignore these early warning signs; reconnaissance is almost always followed by a targeted exploit attempt.`;
                chartRules = `  f1["FACT: known(yes, port_scan)"] --> r1["RULE: verify(port_scan)"]\n  r1 --> c{"CONCLUSION: threat(reconnaissance)"}\n  f2["FACT: known(yes, multiple_failed_logins)"] --> r2["RULE: verify(multiple_failed_logins)"]\n  r2 --> c`;
            }

            const chartHtml = chartRules ? `\n\n### 🔄 Inference Trace Diagram\n\`\`\`mermaid\nflowchart LR\n${chartRules}\n\`\`\`` : '';

            // Auto-reset
            currentSession.knownFacts = [];
            isAsking = false;
            
            return res.json({ 
                terminalOutput,
                reply: `## 🚨 EXPERT DIAGNOSIS: ${formattedThreat}
Based on our consultation, my inference engine has definitively diagnosed a **${formattedThreat}**.

**Calculated Risk Score:** ${score}/10

### 🛡️ Immediate Actions Required:
${richMitigation}
${chartHtml}
`
            });
        }
        else if (resultType === 'ask') {
            isAsking = true;
            currentQuestion = symptom;
            return res.json({ 
                terminalOutput,
                reply: QUESTION_MAP[symptom] || `Is the following true: ${symptom}?`, 
                isAsking: true 
            });
        } 
        else {
            currentSession.knownFacts = [];
            currentSession.excludedThreats = [];
            currentSession.lastThreat = null;
            isAsking = false;
            return res.json({
                terminalOutput,
                reply: `### ❌ No Definite Conclusion\nI have analyzed all available symptoms and could not definitively prove any known critical attack patterns. \n\nPlease continue monitoring the network.`
            });
        }
    });
});

app.listen(port, () => {
    console.log(`CyberPro Dashboard UI running at http://localhost:${port}`);
});
