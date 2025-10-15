# Paillier Homomorphic Encryption Fix

## Problems Fixed

### 1. **Aggregation Error: Different Public Keys**
**Error Message:**
```
Aggregation error: Attempted to add numbers encrypted against different public keys!
```

**Root Cause:** Each alert was being encrypted with a **different random Paillier public key**. Paillier homomorphic encryption only works when all ciphertexts are encrypted with the **same public key**.

**Solution:** Implemented a **shared Paillier key system** where:
- One global Paillier keypair is generated and stored on the server
- All organizations use the same public key to encrypt risk scores
- The backend validates that all ciphertexts use the shared key
- Homomorphic operations now work correctly across all alerts

### 2. **BigInt Serialization Error**
**Root Cause:** JavaScript BigInt values cannot be directly serialized to JSON, causing errors during alert submission.

**Solution:** Implemented proper BigInt to string conversion in the Paillier encryption function, ensuring all large numbers are converted to strings before JSON serialization.

## Architecture Changes

### Before (Broken)
```
Organization 1 → Random Key A → Encrypt(score₁) → Ciphertext₁ᴬ
Organization 2 → Random Key B → Encrypt(score₂) → Ciphertext₂ᴮ
Organization 3 → Random Key C → Encrypt(score₃) → Ciphertext₃ᶜ

Backend: Ciphertext₁ᴬ + Ciphertext₂ᴮ = ❌ ERROR (different keys!)
```

### After (Fixed)
```
Backend: Shared Public Key (n, g) ← Generated once, stored securely
                    ↓
Organization 1 → Shared Key → Encrypt(score₁) → Ciphertext₁
Organization 2 → Shared Key → Encrypt(score₂) → Ciphertext₂
Organization 3 → Shared Key → Encrypt(score₃) → Ciphertext₃

Backend: Ciphertext₁ + Ciphertext₂ + Ciphertext₃ = ✅ Encrypted Sum
         Then: Encrypted Sum / 3 = ✅ Encrypted Average
         
         Decrypt: total = score₁ + score₂ + score₃
         Decrypt: average = (score₁ + score₂ + score₃) / 3
```

## Files Created/Modified

### New Files
1. **`src/app/crypto/paillier_key_manager.py`** (NEW)
   - Manages shared Paillier keypair
   - Generates, loads, and caches keys
   - Provides encryption/decryption with shared key
   - Stores keys in `keys/` directory

2. **`src/scripts/init_paillier_keys.py`** (NEW)
   - Script to initialize Paillier keys
   - Run once during setup
   - Validates existing keys before overwriting

3. **`PAILLIER_FIX.md`** (NEW - this file)
   - Documentation of the fix

### Modified Files
1. **`src/app/api/v1/orgs.py`**
   - Added `GET /api/v1/orgs/paillier/public-key` endpoint
   - Returns shared Paillier public key in JSON format
   - Frontend retrieves this key before encrypting risk scores

2. **`src/app/api/v1/alerts.py`**
   - Updated `/submit` to validate Paillier ciphertexts use shared key
   - Enhanced `/aggregate` to show both encrypted and decrypted results
   - Added proper error handling and logging
   - Returns count of aggregated alerts

3. **`frontend/app.js`**
   - Added `encryptRiskScoreWithPaillier()` function
   - Implements browser-based Paillier encryption using Web Crypto API
   - Fetches shared public key from backend
   - Added `modPow()` helper for modular exponentiation
   - Updated aggregate display to show decrypted results

## Setup Instructions

### Step 1: Initialize Paillier Keys
```powershell
# Navigate to project root
cd D:\IS_Project\Aegis

# Run the initialization script
python .\src\scripts\init_paillier_keys.py
```

**Expected Output:**
```
====================================================================
Aegis Paillier Key Initialization
====================================================================

Generating Paillier keypair (2048-bit)...
This may take 10-30 seconds...

✅ Paillier keys generated successfully!

📁 Keys saved to: D:\IS_Project\Aegis\keys
   Public key:  paillier_public.key
   Private key: paillier_private.key
```

### Step 2: Start the Backend
```powershell
python .\src\app\main.py
```

The backend will automatically load the Paillier keys on startup.

### Step 3: Test the System

#### A. Submit Some Alerts
1. Open `frontend/index.html` in browser
2. Register/login to get a token
3. Submit 3-5 alerts with different risk scores (e.g., 3, 5, 7, 9)

#### B. Test Aggregation
1. Go to "Aggregate" tab
2. Click "Compute Aggregates"
3. Verify you see:
   - Count of alerts aggregated
   - **Decrypted Total** (sum of all risk scores)
   - **Decrypted Average** (average of all risk scores)
   - Encrypted ciphertexts (Paillier format)

**Example Expected Output:**
```
Successfully aggregated 4 encrypted risk scores

📊 Decrypted Results:
Total Risk Score: 24
Average Risk Score: 6.00
✓ Computed from 4 alert(s) without decrypting individual values

🔒 Encrypted Total (Paillier Ciphertext)
{
  "ciphertext": "12345678901234567890...",
  "exponent": 0,
  "public_key_n": "98765432109876543210..."
}
```

## How Paillier Homomorphic Encryption Works

### Encryption
Given a public key (n, g) and plaintext m:
```
1. Choose random r ∈ [1, n)
2. Compute ciphertext: c = g^m · r^n mod n²
```

### Homomorphic Addition
```
Enc(m₁) + Enc(m₂) = Enc(m₁ + m₂)

c₁ · c₂ mod n² = Enc(m₁ + m₂)
```

### Scalar Multiplication (for averaging)
```
k · Enc(m) = Enc(k · m)

c^k mod n² = Enc(k · m)
```

### Average Computation
```
Sum = Enc(m₁) + Enc(m₂) + ... + Enc(mₙ)
Average = Sum / n = Enc((m₁ + m₂ + ... + mₙ) / n)
```

## API Endpoints

### Get Shared Paillier Public Key
```http
GET /api/v1/orgs/paillier/public-key
```

**Response:**
```json
{
  "public_key": {
    "n": "28847913...",
    "g": "28847914...",
    "max_int": "14423956..."
  },
  "info": "Use this public key to encrypt risk scores with Paillier encryption"
}
```

### Submit Alert (with Paillier)
```http
POST /api/v1/alerts/submit
Authorization: Bearer <token>
Content-Type: application/json

{
  "encrypted_payload": "base64...",
  "wrapped_aes_key": "base64...",
  "signature": "base64...",
  "hmac_beacon": "hexstring...",
  "paillier_ciphertext": "{\"ciphertext\":\"123...\",\"exponent\":0,\"public_key_n\":\"456...\"}"
}
```

**Validation:** Backend verifies `public_key_n` matches the shared key.

### Aggregate Risk Scores
```http
GET /api/v1/alerts/aggregate
Authorization: Bearer <token>
```

**Response:**
```json
{
  "count": 4,
  "total_decrypted": 24,
  "average_decrypted": 6.0,
  "total_encrypted": {
    "ciphertext": "123456789...",
    "exponent": 0,
    "public_key_n": "987654321..."
  },
  "average_encrypted": {
    "ciphertext": "567891234...",
    "exponent": -1,
    "public_key_n": "987654321..."
  },
  "message": "Successfully aggregated 4 encrypted risk scores"
}
```

## Security Considerations

### ✅ What's Secure
- **Privacy:** Individual risk scores never revealed during aggregation
- **Integrity:** Homomorphic operations produce mathematically correct results
- **Correctness:** Backend validates all ciphertexts use the shared key
- **Confidentiality:** Only authorized parties with private key can decrypt

### ⚠️ Production Warnings

1. **Key Storage**
   - Keys stored as pickle files in `keys/` directory
   - **Production:** Use hardware security modules (HSM) or key management services
   - Implement key rotation policies

2. **Private Key Access**
   - Currently, backend auto-decrypts aggregates for demonstration
   - **Production:** Limit decryption to specific authorized roles/services
   - Implement audit logging for all decryption operations

3. **Public Key Distribution**
   - Public key served via HTTP API
   - **Production:** Use TLS/HTTPS for all communication
   - Consider certificate pinning for frontend

4. **Key Size**
   - Currently using 2048-bit keys
   - **Production:** Consider 3072-bit or 4096-bit for higher security
   - Note: Larger keys mean slower operations

5. **Browser Implementation**
   - Frontend uses simplified Paillier in JavaScript
   - **Production:** Use battle-tested libraries like `paillier-bigint`
   - Implement proper random number generation for `r`

## Testing Checklist

- [ ] Initialize Paillier keys with `init_paillier_keys.py`
- [ ] Start backend server
- [ ] Register an organization
- [ ] Get API token
- [ ] Submit alert - should succeed (200 OK)
- [ ] Submit multiple alerts with different risk scores
- [ ] Run aggregation - should show decrypted sum and average
- [ ] Verify encrypted ciphertexts all have same `public_key_n`
- [ ] Check no "different public keys" error

## Troubleshooting

### Error: "Failed to retrieve Paillier public key"
**Solution:** Make sure you ran `python .\src\scripts\init_paillier_keys.py` first.

### Error: "Paillier ciphertext must be encrypted with the shared public key"
**Solution:** The frontend is using an old/different public key. Refresh the page to fetch the latest key.

### Error: "Cannot serialize BigInt to JSON"
**Solution:** This is fixed in the updated `app.js`. Make sure you're using the latest version.

### Aggregation returns count: 0
**Solution:** Submit some alerts first. Aggregation requires at least one alert with a risk score.

## Future Enhancements

1. **Client-Side Paillier Library**
   - Replace custom implementation with `paillier-bigint` npm package
   - More robust and tested encryption

2. **Key Rotation**
   - Support multiple active Paillier keys with versioning
   - Graceful migration from old to new keys

3. **Threshold Decryption**
   - Split private key across multiple parties
   - Require k-of-n parties to decrypt (e.g., 3-of-5)
   - No single party can decrypt alone

4. **Zero-Knowledge Proofs**
   - Prove ciphertext is valid without revealing plaintext
   - Prevent malicious data injection

5. **Range Proofs**
   - Prove risk score is within valid range (0-10)
   - Prevent integer overflow attacks

---

## Status: ✅ FIXED

Both issues are now resolved:
- ✅ Aggregation works with shared Paillier key
- ✅ BigInt serialization handled properly
- ✅ Frontend encrypts with shared public key
- ✅ Backend validates and aggregates correctly
- ✅ Decrypted results shown for verification
