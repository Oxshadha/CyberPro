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

    function typeWriterTerminal(command, output, speed = 15) {
        const cmdSpan = document.createElement('span');
        cmdSpan.className = 'command';
        cmdSpan.textContent = `> ${command}\n`;
        
        const outSpan = document.createElement('span');
        outSpan.className = 'output';
        
        terminalLog.appendChild(cmdSpan);
        terminalLog.appendChild(outSpan);
        
        let i = 0;
        function type() {
            if (i < output.length) {
                outSpan.textContent += output.charAt(i);
                i++;
                terminalLog.scrollTop = terminalLog.scrollHeight;
                setTimeout(type, speed);
            } else {
                outSpan.textContent += '\n\n';
                terminalLog.scrollTop = terminalLog.scrollHeight;
            }
        }
        type();
    }

    function showScreen(screen) {
        screenInitial.classList.add('hidden');
        screenAsk.classList.add('hidden');
        screenResult.classList.add('hidden');
        
        screen.classList.remove('hidden');
    }

    async function sendAction(actionType, value = '') {
        try {
            if (actionType !== 'reset') {
                document.getElementById('btn-yes').style.display = 'none';
                document.getElementById('btn-no').style.display = 'none';
                askPrompt.innerHTML = `<i data-lucide="loader-2" class="spin"></i> Executing Inference Engine...`;
                lucide.createIcons();
                showScreen(screenAsk);
            }

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
                document.getElementById('btn-yes').style.display = 'inline-block';
                document.getElementById('btn-no').style.display = 'inline-block';
                askPrompt.textContent = data.reply.replace(/[\*\_]/g, '');
                showScreen(screenAsk);
            } 
            else if (data.reply) {
                let htmlContent = marked.parse(data.reply);
                resultContent.innerHTML = htmlContent;
                showScreen(screenResult);
                lucide.createIcons();
                
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
        typeWriterTerminal('sys', 'Initializing inference engine session...\nReady.');
        sendAction('reset');
        showScreen(screenInitial);
        lucide.createIcons(); // Re-initialize icons if DOM changes
    });

    // Initial greeting in terminal
    typeWriterTerminal('sys', 'CyberPro Expert System Loaded. Awaiting facts...');

    // Initialize Lucide Icons
    lucide.createIcons();
});
