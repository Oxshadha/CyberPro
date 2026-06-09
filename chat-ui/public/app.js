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

    async function sendMessage() {
        const text = userInput.value.trim();
        if (!text) return;

        userInput.value = '';
        addMessage(text, true);
        addTypingIndicator();

        try {
            // Check if user clicked a special button (we intercept special keywords or attach action data)
            let payload = { message: text, action: 'chat' };
            if (text === '%%EXPLAIN%%') {
                payload.action = 'explain';
                payload.message = ''; // Don't show in chat
                chatBox.lastChild.remove(); // Remove the fake message bubble
            } else if (text === '%%ALTERNATE%%') {
                payload.action = 'alternate';
                payload.message = ''; 
                chatBox.lastChild.remove(); 
            }

            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            
            removeTypingIndicator();
            
            // If the backend sent back buttons, we append them manually after marked.js parsing
            let htmlContent = marked.parse(data.reply);
            
            if (data.showButtons) {
                htmlContent += `
                    <div style="margin-top: 15px; display: flex; gap: 10px;">
                        <button onclick="document.getElementById('user-input').value='%%EXPLAIN%%'; document.getElementById('send-btn').click();" style="padding: 8px 12px; background: #3b82f6; color: white; border: none; border-radius: 6px; cursor: pointer; font-family: Inter;">🔍 Explain</button>
                        <button onclick="document.getElementById('user-input').value='%%ALTERNATE%%'; document.getElementById('send-btn').click();" style="padding: 8px 12px; background: #10b981; color: white; border: none; border-radius: 6px; cursor: pointer; font-family: Inter;">🔄 Alternate Answer</button>
                    </div>
                `;
            }

            const msgDiv = document.createElement('div');
            msgDiv.className = 'message ai-message';
            const contentDiv = document.createElement('div');
            contentDiv.className = 'message-content';
            contentDiv.innerHTML = htmlContent;
            
            msgDiv.appendChild(contentDiv);
            chatBox.appendChild(msgDiv);
            chatBox.scrollTop = chatBox.scrollHeight;
            
        } catch (error) {
            removeTypingIndicator();
            addMessage('⚠️ Sorry, there was an error connecting to the CyberPro Node.js engine.', false);
        }
    }

    sendBtn.addEventListener('click', sendMessage);
    userInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });
});
