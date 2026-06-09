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
// For a university project, we use a simple global in-memory session.
let currentSession = {
    knownFacts: [], // Stores objects like { yesNo: 'yes', symptom: 'port_scan' }
    excludedThreats: [], // Array of strings (threats to skip for alternate answers)
    lastThreat: null // To support 'explain' feature
};
let isAsking = false;
let currentQuestion = null;

// --- Natural Language Mapping ---
const EVENT_MAP = {
    'server is down': 'service_unavailable',
    'unavailable': 'service_unavailable',
    'offline': 'service_unavailable',
    'high traffic': 'high_network_traffic',
    'ddos': 'high_network_traffic',
    'database error': 'database_errors',
    'sql error': 'database_errors',
    'unauthorized': 'unauthorized_access',
    'breach': 'unauthorized_access',
    'encrypted': 'files_encrypted',
    'ransom': 'ransom_note',
    'weird time': 'unusual_login_times',
    'exfiltration': 'data_exfiltration',
    'port scan': 'port_scan',
    'failed login': 'multiple_failed_logins'
};

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

    // Handle EXPLAIN feature
    if (action === 'explain') {
        if (!currentSession.lastThreat) {
            return res.json({ reply: 'There is no recent diagnosis to explain. Please start a new diagnosis.' });
        }
        const query = `api_explain(${currentSession.lastThreat}).`;
        const swiplCommand = `PATH=$PATH:/Applications/SWI-Prolog.app/Contents/MacOS swipl -s ../cyber_pro.pl -g "${query}" -t halt`;
        
        exec(swiplCommand, (error, stdout, stderr) => {
            const output = stdout.trim();
            const expLine = output.split('\n').find(l => l.startsWith('EXPLANATION='));
            if (expLine) {
                const text = expLine.split('=')[1];
                return res.json({ reply: `### 📖 Detailed Explanation\n\n${text}\n\n*(Use 'New Conversation' or type a new symptom to start over).*` });
            }
            return res.json({ reply: 'Explanation not available.' });
        });
        return;
    }

    // Handle ALTERNATE feature
    if (action === 'alternate') {
        if (!currentSession.lastThreat) {
            return res.json({ reply: 'There is no recent diagnosis to find alternatives for.' });
        }
        currentSession.excludedThreats.push(currentSession.lastThreat);
        // We will run the diagnosis again using the same known facts, but skipping excluded threats!
        // The flow will fall through to the Prolog execution below.
    }

    // 1. Handle Reset
    if (userMessage.includes('reset') || userMessage.includes('start over')) {
        currentSession.knownFacts = [];
        currentSession.excludedThreats = [];
        currentSession.lastThreat = null;
        isAsking = false;
        currentQuestion = null;
        return res.json({ reply: 'Session reset. I am ready. What symptoms are you experiencing?' });
    }

    // 2. Handle Yes/No Answers
    if (isAsking && action === 'chat') {
        if (userMessage.includes('yes') || userMessage.includes('yep') || userMessage.includes('yeah')) {
            currentSession.knownFacts.push({ yesNo: 'yes', symptom: currentQuestion });
        } else if (userMessage.includes('no') || userMessage.includes('nope') || userMessage.includes('nah')) {
            currentSession.knownFacts.push({ yesNo: 'no', symptom: currentQuestion });
        } else {
            return res.json({ reply: `Please answer **yes** or **no** to the question:\n\n*${QUESTION_MAP[currentQuestion]}*` });
        }
        
        isAsking = false;
        currentQuestion = null;
    } 
    // 3. Handle Initial Symptoms
    else if (action === 'chat') {
        let foundAny = false;
        for (const [phrase, event] of Object.entries(EVENT_MAP)) {
            if (userMessage.includes(phrase)) {
                // Check if we already know this fact
                if (!currentSession.knownFacts.find(f => f.symptom === event)) {
                    currentSession.knownFacts.push({ yesNo: 'yes', symptom: event });
                    foundAny = true;
                }
            }
        }
        
        if (!foundAny && currentSession.knownFacts.length === 0) {
            return res.json({
                reply: "I didn't detect any specific security events. Please describe what you are seeing (e.g., 'My server is down' or 'We noticed a port scan')."
            });
        }
    }

    // 4. Build the Prolog query with current state
    let assertStatements = currentSession.knownFacts.map(f => `assert_fact(${f.yesNo}, ${f.symptom})`).join(', ');
    if (!assertStatements) assertStatements = 'true';
    
    // Format the excluded threats list for Prolog: e.g., [ddos, sql_injection]
    const excludedList = `[${currentSession.excludedThreats.join(',')}]`;

    const query = `
        reset_session,
        ${assertStatements},
        api_diagnose(${excludedList}).
    `;

    // 5. Execute Prolog securely
    const swiplCommand = `PATH=$PATH:/Applications/SWI-Prolog.app/Contents/MacOS swipl -s ../cyber_pro.pl -g "${query.trim().replace(/\n/g, ' ')}" -t halt`;

    exec(swiplCommand, (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            if(error.message.includes("swipl: command not found") || error.code === 127) {
                return res.json({ reply: "⚠️ **SWI-Prolog is not installed or not in PATH.**" });
            }
            return res.status(500).json({ reply: "Error communicating with the Prolog inference engine." });
        }
        
        // 6. Parse Prolog's Stateful Output
        const output = stdout.trim();
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

        // 7. Decide next action based on Prolog's instruction
        if (resultType === 'ask') {
            isAsking = true;
            currentQuestion = symptom;
            const humanQuestion = QUESTION_MAP[symptom] || `Are you experiencing ${symptom.replace(/_/g, ' ')}?`;
            return res.json({ reply: `Hmm, I need more information to confirm a diagnosis.\n\n**${humanQuestion}** (yes/no)` });
        } 
        else if (resultType === 'found') {
            const formattedThreat = threat.replace(/_/g, ' ').toUpperCase();
            
            // Save the last threat found to enable EXPLAIN and ALTERNATE features
            currentSession.lastThreat = threat;
            
            // Note: We don't clear knownFacts here because the user might ask for an Alternate Answer!
            isAsking = false;
            
            return res.json({ 
                reply: `### 🚨 EXPERT DIAGNOSIS: ${formattedThreat} DETECTED
Based on our consultation, my inference engine has definitively diagnosed a **${formattedThreat}**.

**Calculated Risk Score:** ${score}/10

### 🛡️ Immediate Actions Required:
${mitigation}`,
                showButtons: true 
            });
        } 
        else {
            // Auto-reset when exhausted
            currentSession.knownFacts = [];
            currentSession.excludedThreats = [];
            currentSession.lastThreat = null;
            isAsking = false;
            return res.json({
                reply: `I have analyzed all available symptoms and could not definitively prove any more known critical attack patterns. \n\nPlease continue monitoring the network. *(Session reset).*`
            });
        }
    });
});

app.listen(port, () => {
    console.log(`CyberPro Chat UI running at http://localhost:${port}`);
});
