// Crypto utilities
let cachedPrivateKeyPem = null;
let cachedPrivateKey = null;
let cachedPaillierPublicKey = null;
let cachedDerivedKey = null;
let cachedSaltBase64 = null;
let cachedHMACKey = null;

async function deriveKeyFromPassword(password, saltBase64) {
    if (cachedDerivedKey && cachedSaltBase64 === saltBase64) {
        return cachedDerivedKey;
    }
    
    const encoder = new TextEncoder();
    const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
    
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    
    cachedDerivedKey = await crypto.subtle.deriveKey(
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
    
    cachedSaltBase64 = saltBase64;
    return cachedDerivedKey;
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
    if (cachedPrivateKeyPem) {
        return cachedPrivateKeyPem;
    }
    
    const cachedData = sessionStorage.getItem('encryptedKeyData');
    let data;
    
    if (cachedData) {
        data = JSON.parse(cachedData);
    } else {
        const response = await fetch(`${API_BASE_URL}/orgs/me/encrypted-key`, {
            headers: { 'Authorization': `Bearer ${session.token}` }
        });
        if (!response.ok) throw new Error('Failed to fetch key');
        data = await response.json();
    }
    
    cachedPrivateKeyPem = await decryptPrivateKey(
        data.encrypted_private_key,
        session.password,
        data.salt,
        data.nonce
    );
    
    return cachedPrivateKeyPem;
}

async function getImportedPrivateKey() {
    if (cachedPrivateKey) {
        return cachedPrivateKey;
    }
    
    const pem = await fetchAndDecryptPrivateKey();
    cachedPrivateKey = await importPrivateKey(pem);
    return cachedPrivateKey;
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
    if (!cachedHMACKey) {
        const encoder = new TextEncoder();
        cachedHMACKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(key),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
    }
    
    const encoder = new TextEncoder();
    const signature = await crypto.subtle.sign(
        'HMAC',
        cachedHMACKey,
        encoder.encode(data)
    );
    
    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function unwrapAESKey(wrappedKeyBase64, privateKeyPem) {
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

async function encryptRiskScorePaillier(riskScore, publicKeyData) {
    if (typeof paillierBigint === 'undefined') {
        throw new Error('Paillier library not loaded');
    }
    
    const pubKey = new paillierBigint.PublicKey(
        BigInt(publicKeyData.n),
        BigInt(publicKeyData.g)
    );
    
    const encrypted = pubKey.encrypt(BigInt(riskScore));
    
    return JSON.stringify({
        ciphertext: encrypted.toString(),
        exponent: 0,
        public_key_n: publicKeyData.n.toString()
    });
}

window.encryptRiskScorePaillier = encryptRiskScorePaillier;

function getPaillierPublicKey() {
    if (cachedPaillierPublicKey) {
        return cachedPaillierPublicKey;
    }
    
    const paillierKeyData = JSON.parse(sessionStorage.getItem('paillierKey'));
    if (typeof paillierBigint !== 'undefined') {
        cachedPaillierPublicKey = new paillierBigint.PublicKey(
            BigInt(paillierKeyData.n),
            BigInt(paillierKeyData.g)
        );
    }
    
    return cachedPaillierPublicKey;
}

async function verifySignature(data, signatureBase64, publicKeyPem) {
    try {
        const pemContents = publicKeyPem
            .replace(/-----BEGIN PUBLIC KEY-----/, '')
            .replace(/-----END PUBLIC KEY-----/, '')
            .replace(/\s/g, '');
        
        const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
        
        const publicKey = await crypto.subtle.importKey(
            'spki',
            binaryDer,
            { name: 'RSA-PSS', hash: 'SHA-256' },
            false,
            ['verify']
        );
        
        const encoder = new TextEncoder();
        const dataBytes = encoder.encode(data);
        const signatureBytes = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));
        
        const isValid = await crypto.subtle.verify(
            { name: 'RSA-PSS', saltLength: 222 },
            publicKey,
            signatureBytes,
            dataBytes
        );
        
        return isValid;
    } catch (error) {
        console.error('Signature verification error:', error);
        return false;
    }
}

window.verifySignature = verifySignature;

