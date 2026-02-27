/**
 * renderer.js (Web Version)
 * Directly interacts with CipherLogic globally.
 */

const methodSelect = document.getElementById('method-select');
const passwordInput = document.getElementById('password-input');
const togglePasswordBtn = document.getElementById('toggle-password');
const inputText = document.getElementById('input-text');
const outputText = document.getElementById('output-text');
const btnEncrypt = document.getElementById('btn-encrypt');
const btnDecrypt = document.getElementById('btn-decrypt');
const clearInputBtn = document.getElementById('clear-input');
const copyResultBtn = document.getElementById('copy-result');
const statusText = document.getElementById('status-text');
const statusBar = document.getElementById('status-bar');
const themeToggleBtn = document.getElementById('theme-toggle');

function updateStatus(message, type = 'info') {
    statusText.innerText = message;
    statusBar.classList.remove('status-success', 'status-error');
    if (type === 'success') statusBar.classList.add('status-success');
    else if (type === 'error') statusBar.classList.add('status-error');
}

function handleAction(action) {
    const method = methodSelect.value;
    const text = inputText.value.trim();
    const password = passwordInput.value;

    if (!text) {
        updateStatus('処理するテキストを入力してください。', 'error');
        return;
    }
    if (!password) {
        updateStatus('セキュリティのためパスワードが必要です。', 'error');
        return;
    }

    updateStatus(`${action === 'encrypt' ? '暗号化' : '復号化'}中...`);

    try {
        let result;
        if (action === 'encrypt') {
            result = CipherLogic.encrypt(method, text, password);
        } else {
            result = CipherLogic.decrypt(method, text, password);
        }
        outputText.value = result;
        updateStatus(`${action === 'encrypt' ? '暗号化' : '復号化'}が完了しました！`, 'success');
    } catch (err) {
        updateStatus('エラーが発生しました: ' + err.message, 'error');
        console.error(err);
    }
}

// Theme Toggle
function updateThemeUI(isDark) {
    const icon = themeToggleBtn.querySelector('.material-symbols-outlined');
    if (isDark) {
        document.documentElement.classList.add('dark-mode');
        document.documentElement.classList.remove('light-mode');
        icon.innerText = 'light_mode';
    } else {
        document.documentElement.classList.add('light-mode');
        document.documentElement.classList.remove('dark-mode');
        icon.innerText = 'dark_mode';
    }
}

themeToggleBtn.addEventListener('click', () => {
    const isDark = document.documentElement.classList.contains('dark-mode');
    updateThemeUI(!isDark);
});

btnEncrypt.addEventListener('click', () => handleAction('encrypt'));
btnDecrypt.addEventListener('click', () => handleAction('decrypt'));

clearInputBtn.addEventListener('click', () => {
    inputText.value = '';
    updateStatus('入力をクリアしました。');
});

copyResultBtn.addEventListener('click', () => {
    const text = outputText.value;
    if (text) {
        navigator.clipboard.writeText(text);
        const icon = copyResultBtn.querySelector('.material-symbols-outlined');
        const originalIcon = icon.innerText;
        icon.innerText = 'check';
        updateStatus('コピーしました！', 'success');
        setTimeout(() => { icon.innerText = originalIcon; }, 2000);
    }
});

togglePasswordBtn.addEventListener('click', () => {
    const icon = togglePasswordBtn.querySelector('.material-symbols-outlined');
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.innerText = 'visibility_off';
    } else {
        passwordInput.type = 'password';
        icon.innerText = 'visibility';
    }
});

// Check system preference on load
document.addEventListener('DOMContentLoaded', () => {
    const isDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    updateThemeUI(isDark);
    updateStatus('待機中');
});
