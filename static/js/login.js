/**
 * 使用 RSA-OAEP 公钥加密登录密码
 * 防止 F12 Network 面板中看到明文密码
 */
async function encryptPassword() {
    const passwordField = document.getElementById('password');
    const password = passwordField.value;
    const btn = document.getElementById('loginBtn');
    btn.disabled = true;
    btn.textContent = '加密中...';

    try {
        // 1. 从服务端获取 RSA 公钥
        const resp = await fetch('/public-key');
        const pem = await resp.text();

        // 2. 解析 PEM 格式公钥（去掉 header/footer/换行）
        let pemBody = pem;
        const markers = ['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----'];
        markers.forEach(m => pemBody = pemBody.replace(m, ''));
        pemBody = pemBody.replace(/\n/g, '').replace(/\r/g, '');

        const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));

        // 3. 导入公钥
        const publicKey = await crypto.subtle.importKey(
            'spki',
            binaryDer.buffer,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['encrypt']
        );

        // 4. 加密密码
        const encrypted = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKey,
            new TextEncoder().encode(password)
        );

        // 5. 将密文 base64 编码后替换到表单密码字段
        const encryptedArray = new Uint8Array(encrypted);
        let binary = '';
        encryptedArray.forEach(b => binary += String.fromCharCode(b));
        passwordField.value = btoa(binary);

        return true; // 允许表单提交
    } catch (e) {
        console.error('RSA 加密失败:', e);
        btn.disabled = false;
        btn.textContent = '登 录';
        alert('加密失败，请刷新页面重试');
        return false; // 阻止表单提交
    }
}
