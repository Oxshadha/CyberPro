document.addEventListener('DOMContentLoaded', () => {
    // Screens
    const screenInitial = document.getElementById('screen-initial');
    const screenAsk = document.getElementById('screen-ask');
    const screenResult = document.getElementById('screen-result');
    
    // Elements
    const askPrompt = document.getElementById('ask-prompt');
    const resultContent = document.getElementById('result-content');
    const terminalLog = document.getElementById('terminal-log');
    const terminalPanel = document.querySelector('.terminal-panel');
    
    // Buttons
    const resetBtn = document.getElementById('reset-btn');
    const toggleTerminalBtn = document.getElementById('toggle-terminal-btn');
    const btnYes = document.getElementById('btn-yes');
    const btnNo = document.getElementById('btn-no');
    const symptomCards = document.querySelectorAll('.symptom-card');

    function appendTerminal(command, output) {
        const cmdSpan = document.createElement('span');
        cmdSpan.className = 'command';
        cmdSpan.textContent = `> ${command}\n`;
        
        const outSpan = document.createElement('span');
        outSpan.className = 'output';
        outSpan.textContent = `${output}\n\n`;
        
        terminalLog.appendChild(cmdSpan);
        terminalLog.appendChild(outSpan);
        terminalLog.scrollTop = terminalLog.scrollHeight;
    }

    function showScreen(screen) {
        screenInitial.classList.add('hidden');
        screenAsk.classList.add('hidden');
        screenResult.classList.add('hidden');
        
        screen.classList.remove('hidden');
    }

    async function sendAction(actionType, value = '') {
        try {
            const payload = { action: actionType, message: value };
            
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await response.json();

            // Log to terminal
            if (data.terminalOutput) {
                appendTerminal(data.terminalOutput.command, data.terminalOutput.output);
            }

            // Handle Response
            if (actionType === 'reset') {
                // Do not display the reset reply on screen, it's just an internal confirmation
                return;
            }

            if (data.isAsking) {
                askPrompt.textContent = data.reply.replace(/[\*\_]/g, '');
                showScreen(screenAsk);
            } 
            else if (data.reply) {
                let htmlContent = marked.parse(data.reply);
                resultContent.innerHTML = htmlContent;
                showScreen(screenResult);
                
                // Render mermaid
                if (htmlContent.includes('language-mermaid')) {
                    document.querySelectorAll('.language-mermaid').forEach(el => {
                        const mermaidDiv = document.createElement('div');
                        mermaidDiv.className = 'mermaid';
                        mermaidDiv.textContent = el.textContent;
                        el.parentElement.replaceWith(mermaidDiv);
                    });
                    mermaid.run();
                }
            }
        } catch (error) {
            console.error(error);
            alert("Error communicating with server.");
        }
    }

    // Event Listeners
    symptomCards.forEach(card => {
        card.addEventListener('click', () => {
            const symptom = card.getAttribute('data-symptom');
            sendAction('initial_symptom', symptom);
        });
    });

    btnYes.addEventListener('click', () => sendAction('answer', 'yes'));
    btnNo.addEventListener('click', () => sendAction('answer', 'no'));

    toggleTerminalBtn.addEventListener('click', () => {
        terminalPanel.classList.toggle('hidden');
    });

    resetBtn.addEventListener('click', () => {
        terminalLog.innerHTML = '';
        appendTerminal('sys', 'Initializing inference engine session...\nReady.');
        sendAction('reset');
        showScreen(screenInitial);
    });

    // Initial greeting in terminal
    appendTerminal('sys', 'CyberPro Expert System Loaded. Awaiting facts...');
});
