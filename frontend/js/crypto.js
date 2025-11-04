// Crypto utilities
async function deriveKeyFromPassword(password, saltBase64) {
    const encoder = new TextEncoder();
    const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
    
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    
    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
}

async function decryptPrivateKey(encryptedBase64, password, saltBase64, nonceBase64) {
    const aesKey = await deriveKeyFromPassword(password, saltBase64);
    const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
    const nonce = Uint8Array.from(atob(nonceBase64), c => c.charCodeAt(0));
    
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey,
        encrypted
    );
    
    return new TextDecoder().decode(decrypted);
}

async function fetchAndDecryptPrivateKey() {
    const response = await fetch(`${API_BASE_URL}/orgs/me/encrypted-key`, {
        headers: { 'Authorization': `Bearer ${session.token}` }
    });
    
    if (!response.ok) throw new Error('Failed to fetch key');
    
    const data = await response.json();
    return await decryptPrivateKey(
        data.encrypted_private_key,
        session.password,
        data.salt,
        data.nonce
    );
}

async function importPrivateKey(pemString) {
    const pemContents = pemString
        .replace(/-----BEGIN PRIVATE KEY-----/, '')
        .replace(/-----END PRIVATE KEY-----/, '')
        .replace(/\s/g, '');
    
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    
    return await crypto.subtle.importKey(
        'pkcs8',
        binaryDer,
        { name: 'RSA-PSS', hash: 'SHA-256' },
        false,
        ['sign']
    );
}

async function signData(data, privateKey) {
    // data can be either string or ArrayBuffer
    let dataToSign;
    if (typeof data === 'string') {
        const encoder = new TextEncoder();
        dataToSign = encoder.encode(data);
    } else {
        dataToSign = data;
    }
    
    const signature = await crypto.subtle.sign(
        { name: 'RSA-PSS', saltLength: 222 },  // MAX_LENGTH for 2048-bit RSA
        privateKey,
        dataToSign
    );
    
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function encryptAlert(alertData) {
    const aesKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt']
    );
    
    const encoder = new TextEncoder();
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey,
        encoder.encode(JSON.stringify(alertData))
    );
    
    const exportedKey = await crypto.subtle.exportKey('raw', aesKey);
    const combined = new Uint8Array(nonce.length + encrypted.byteLength);
    combined.set(nonce, 0);
    combined.set(new Uint8Array(encrypted), nonce.length);
    
    return {
        encryptedPayload: btoa(String.fromCharCode(...combined)),
        aesKey: exportedKey
    };
}

async function wrapAESKey(aesKey, publicKeyPem) {
    const pemContents = publicKeyPem
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s/g, '');
    
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    
    const publicKey = await crypto.subtle.importKey(
        'spki',
        binaryDer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
    );
    
    const wrapped = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        publicKey,
        aesKey
    );
    
    return btoa(String.fromCharCode(...new Uint8Array(wrapped)));
}

async function computeHMACBeacon(data, key = 'shared-secret') {
    const encoder = new TextEncoder();
    const keyData = await crypto.subtle.importKey(
        'raw',
        encoder.encode(key),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    const signature = await crypto.subtle.sign(
        'HMAC',
        keyData,
        encoder.encode(data)
    );
    
    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function unwrapAESKey(wrappedKeyBase64, privateKeyPem) {
    // Import private key for RSA-OAEP decryption (not RSA-PSS signing)
    const pemContents = privateKeyPem
        .replace(/-----BEGIN PRIVATE KEY-----/, '')
        .replace(/-----END PRIVATE KEY-----/, '')
        .replace(/\s/g, '');
    
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    
    const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        binaryDer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt']
    );
    
    const wrappedKeyBytes = base64ToArrayBuffer(wrappedKeyBase64);
    
    const unwrappedKey = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        wrappedKeyBytes
    );
    
    return await crypto.subtle.importKey(
        'raw',
        unwrappedKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
}

async function decryptAlert(encryptedPayloadBase64, aesKey) {
    const combined = base64ToArrayBuffer(encryptedPayloadBase64);
    const combinedArray = new Uint8Array(combined);
    
    const nonce = combinedArray.slice(0, 12);
    const encryptedData = combinedArray.slice(12);
    
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey,
        encryptedData
    );
    
    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decrypted));
}
