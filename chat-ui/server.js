const express = require('express');
const { exec } = require('child_process');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// The known valid events mapped exactly to Prolog KB
const VALID_EVENTS = [
    'port_scan',
    'sql_injection_attempt',
    'suspicious_login',
    'malware_signature',
    'data_exfiltration',
    'privilege_escalation',
    'unauthorized_access'
];

app.post('/api/chat', (req, res) => {
    const userMessage = req.body.message.toLowerCase();
    
    // 1. Extract keywords
    const detectedEvents = VALID_EVENTS.filter(event => 
        userMessage.includes(event.replace(/_/g, ' ')) || 
        userMessage.includes(event)
    );

    if (detectedEvents.length === 0) {
        return res.json({
            reply: "I didn't detect any specific actionable security events in your message. Please provide more details (e.g., 'We noticed a port scan and a suspicious login.')."
        });
    }

    // 2. Build the Prolog query
    // We will clear alerts, add the detected ones, and query primary_threat, calculate_risk, and mitigation.
    
    const addStatements = detectedEvents.map(e => `add_alert(${e})`).join(', ');
    
    // Construct the query string.
    const query = `
        clear_alerts,
        ${addStatements},
        ( primary_threat(Threat) -> 
            (
                threat(Threat, Level),
                mitigation(Threat, Mit),
                get_all_alerts(Alerts),
                calculate_risk(Alerts, Score),
                writeln('THREAT='), writeln(Threat),
                writeln('LEVEL='), writeln(Level),
                writeln('SCORE='), writeln(Score),
                writeln('MITIGATION='), writeln(Mit)
            )
        ; 
            writeln('THREAT=none')
        ).
    `;

    // 3. Execute Prolog securely via child process
    const command = `swipl -s ../cyber_pro.pl -g "${query.trim().replace(/\n/g, ' ')}" -t halt`;

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            // Provide a fallback response if SWI-Prolog is not installed locally
            if(error.message.includes("swipl: command not found") || error.code === 127) {
                return res.json({ reply: "⚠️ **SWI-Prolog is not installed or not in PATH.** Please install SWI-Prolog (`brew install swi-prolog` or download it) to run the logic engine." });
            }
            return res.status(500).json({ reply: "Error communicating with the Prolog inference engine." });
        }
        
        // 4. Parse output
        const output = stdout.trim();
        if (output.includes('THREAT=none') || !output) {
            return res.json({
                reply: `I recorded the events: **${detectedEvents.join(', ')}**. However, based on the current rules, this does not constitute a critical attack pattern yet. Monitor the situation.`
            });
        }

        // Extracting values
        let threat = '', level = '', score = '', mitigation = '';
        const lines = output.split('\\n');
        for (let i = 0; i < lines.length; i++) {
            if (lines[i] === 'THREAT=') threat = lines[i+1];
            if (lines[i] === 'LEVEL=') level = lines[i+1];
            if (lines[i] === 'SCORE=') score = lines[i+1];
            if (lines[i] === 'MITIGATION=') mitigation = lines[i+1];
        }

        // 5. Format friendly response
        const formattedThreat = threat.replace(/_/g, ' ').toUpperCase();
        
        const friendlyReply = `### 🚨 ALERT: ${formattedThreat} DETECTED
Based on your report of **${detectedEvents.join(', ').replace(/_/g, ' ')}**, my inference engine has diagnosed a **${formattedThreat}**.

**Severity Level:** ${level.toUpperCase()}
**Calculated Risk Score:** ${score}

### 🛡️ Immediate Actions Required:
${mitigation}`;

        res.json({ reply: friendlyReply });
    });
});

app.listen(port, () => {
    console.log(`CyberPro Chat UI running at http://localhost:${port}`);
});
