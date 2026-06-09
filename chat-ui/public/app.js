document.addEventListener('DOMContentLoaded', () => {
    const chatBox = document.getElementById('chat-box');
    const userInput = document.getElementById('user-input');
    const sendBtn = document.getElementById('send-btn');

    function addMessage(text, isUser = false) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `message ${isUser ? 'user-message' : 'ai-message'}`;
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        
        if (isUser) {
            contentDiv.textContent = text;
        } else {
            // Render markdown using marked.js
            contentDiv.innerHTML = marked.parse(text);
        }

        msgDiv.appendChild(contentDiv);
        chatBox.appendChild(msgDiv);
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    function addTypingIndicator() {
        const msgDiv = document.createElement('div');
        msgDiv.className = 'message ai-message typing';
        msgDiv.id = 'typing-indicator';
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content typing-indicator';
        contentDiv.innerHTML = '<div class="dot"></div><div class="dot"></div><div class="dot"></div>';
        
        msgDiv.appendChild(contentDiv);
        chatBox.appendChild(msgDiv);
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    function removeTypingIndicator() {
        const indicator = document.getElementById('typing-indicator');
        if (indicator) {
            indicator.remove();
        }
    }

    const newChatBtn = document.getElementById('new-chat-btn');

    async function sendMessage(overrideText = null, actionOverride = null) {
        const text = overrideText !== null ? overrideText : userInput.value.trim();
        if (!text && !actionOverride) return;

        if (overrideText === null) {
            userInput.value = '';
            addMessage(text, true);
        }

        addTypingIndicator();

        try {
            let payload = { message: text, action: actionOverride || 'chat' };

            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            
            removeTypingIndicator();
            
            let htmlContent = marked.parse(data.reply);
            
            if (data.showButtons) {
                htmlContent += `
                    <div style="margin-top: 15px; display: flex; gap: 10px;">
                        <button onclick="window.sendExplain()" style="padding: 8px 12px; background: #3b82f6; color: white; border: none; border-radius: 6px; cursor: pointer; font-family: Inter;">🔍 Explain</button>
                    </div>
                `;
            }

            // Create and append the AI message
            const msgDiv = document.createElement('div');
            msgDiv.className = 'message ai-message';
            const contentDiv = document.createElement('div');
            contentDiv.className = 'message-content';
            contentDiv.innerHTML = htmlContent;
            
            msgDiv.appendChild(contentDiv);
            chatBox.appendChild(msgDiv);
            chatBox.scrollTop = chatBox.scrollHeight;

            // Render mermaid diagrams if any are present
            if (htmlContent.includes('language-mermaid')) {
                document.querySelectorAll('.language-mermaid').forEach(el => {
                    const mermaidDiv = document.createElement('div');
                    mermaidDiv.className = 'mermaid';
                    mermaidDiv.textContent = el.textContent;
                    el.parentElement.replaceWith(mermaidDiv);
                });
                mermaid.run();
            }
            
        } catch (error) {
            removeTypingIndicator();
            addMessage('⚠️ Sorry, there was an error connecting to the CyberPro Node.js engine.', false);
        }
    }

    // Expose a global function for the Explain button
    window.sendExplain = function() {
        sendMessage('', 'explain');
    };

    sendBtn.addEventListener('click', () => sendMessage());
    userInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    newChatBtn.addEventListener('click', () => {
        chatBox.innerHTML = `
            <div class="message ai-message">
                <div class="message-content">
                    Hello! I am CyberPro, your AI SOC Triage Assistant. Describe any suspicious network events you are experiencing, and I will analyze the threat for you.
                    <br><br>
                    *Examples: "port scan", "malware signature", "data exfiltration", "suspicious login"*
                </div>
            </div>`;
        sendMessage('reset', 'chat'); // tell backend to reset session silently
    });
});
