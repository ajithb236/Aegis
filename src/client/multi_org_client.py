
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
import base64
import json
import os
from app.crypto import rsa_utils, aes_utils, hmac_utils, paillier_utils

BASE_URL = "http://localhost:8000/api/v1"


class OrgClient:
    """Client for a single organization"""
    
    def __init__(self, org_id: str, org_name: str):
        self.org_id = org_id
        self.org_name = org_name
        self.token = None
        self.private_key = None
        self.public_key = None
    
    def register(self):
        """Register the organization"""
        print(f"\n{'='*60}")
        print(f"REGISTERING: {self.org_name} ({self.org_id})")
        print(f"{'='*60}")
        
        response = requests.post(
            f"{BASE_URL}/orgs/register",
            json={
                "org_id": self.org_id,
                "org_name": self.org_name
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Registration successful!")
            print(f"  Private key: {data['private_key_path']}")
            print(f"  Public key: {data['public_key_path']}")
            
            # Load the private key
            priv_key_path = Path(data['private_key_path'])
            with open(priv_key_path, 'rb') as f:
                self.private_key = rsa_utils.deserialize_private_key(f.read())
            
            return data
        elif response.status_code == 409:
            print(f"✓ Organization already registered")
            # Load existing private key
            priv_key_path = Path(__file__).resolve().parents[2] / "keys" / f"{self.org_id}_private.pem"
            if priv_key_path.exists():
                with open(priv_key_path, 'rb') as f:
                    self.private_key = rsa_utils.deserialize_private_key(f.read())
            return None
        else:
            print(f"Registration failed: {response.text}")
            return None
    
    def get_token(self):
        """Get API token for authentication"""
        print(f"\nGetting API token for {self.org_id}...")
        
        response = requests.post(
            f"{BASE_URL}/orgs/token",
            json={"org_id": self.org_id}
        )
        
        if response.status_code == 200:
            data = response.json()
            self.token = data['token']
            print(f"Token obtained: {self.token[:20]}...")
            return self.token
        else:
            print(f"Token request failed: {response.text}")
            return None
    
    def get_headers(self):
        """Get authorization headers"""
        if not self.token:
            raise Exception("No token available. Call get_token() first.")
        return {"Authorization": f"Bearer {self.token}"}
    
    def submit_alert(self, alert_data: dict, risk_score: int):
        """Submit an encrypted alert with Paillier encrypted risk score"""
        print(f"\nSubmitting alert from {self.org_id}...")
        print(f"   Alert data: {alert_data}")
        print(f"   Risk score: {risk_score}")
        
        # 1. Generate AES key and encrypt the payload
        aes_key = os.urandom(32)  # Generate 256-bit AES key
        payload_json = json.dumps(alert_data)
        encrypted_payload_b64 = aes_utils.encrypt_aes_gcm(payload_json.encode(), aes_key)
        
        # 2. Wrap AES key with receiver's public key (simulated)
        receiver_pub_key_path = Path(__file__).resolve().parents[2] / "keys" / "org1_public.pem"
        with open(receiver_pub_key_path, 'rb') as f:
            receiver_pub_key = rsa_utils.deserialize_public_key(f.read())
        wrapped_key = rsa_utils.wrap_key(aes_key, receiver_pub_key)
        
        # 3. Sign the encrypted payload
        encrypted_payload_bytes = base64.b64decode(encrypted_payload_b64)
        signature = rsa_utils.sign_data(self.private_key, encrypted_payload_bytes)
        
        # 4. Generate HMAC beacon for searchability
        hmac_key = b"demo-hmac-beacon-key-32"  # In production, securely share this
        beacon = hmac_utils.compute_hmac(alert_data.get("alert_type", "unknown"), key=hmac_key)
        
        # 5. Encrypt risk score with Paillier
        # Load or generate Paillier public key
        paillier_pub_key, _ = paillier_utils.generate_paillier_keypair()
        encrypted_risk = paillier_utils.encrypt_paillier(paillier_pub_key, risk_score)
        paillier_json = paillier_utils.serialize_to_json(encrypted_risk)
        
        # 6. Prepare alert submission
        alert_submission = {
            "encrypted_payload": encrypted_payload_b64,
            "wrapped_aes_key": base64.b64encode(wrapped_key).decode(),
            "signature": base64.b64encode(signature).decode(),
            "hmac_beacon": beacon,
            "paillier_ciphertext": json.dumps(paillier_json)
        }
        
        # 7. Submit to server
        response = requests.post(
            f"{BASE_URL}/alerts/submit",
            json=alert_submission,
            headers=self.get_headers()
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"Alert submitted successfully!")
            print(f"  Alert ID: {data['alert_id']}")
            return data
        else:
            print(f"Alert submission failed: {response.text}")
            return None
    
    def get_my_info(self):
        """Get organization information"""
        response = requests.get(
            f"{BASE_URL}/orgs/me/info",
            headers=self.get_headers()
        )
        
        if response.status_code == 200:
            return response.json()
        return None
    
    def get_my_alerts(self):
        """Get all alerts submitted by this organization"""
        response = requests.get(
            f"{BASE_URL}/orgs/me/alerts",
            headers=self.get_headers()
        )
        
        if response.status_code == 200:
            return response.json()
        return None


def main():
    """Demonstrate multi-organization workflow"""
    
    print("\n" + "="*60)
    print("MULTI-ORGANIZATION DEMO")
    print("="*60)
    
    # Create multiple organizations
    orgs = [
        OrgClient("org1", "Alpha Security Corp"),
        OrgClient("org2", "Beta Threat Intelligence"),
        OrgClient("org3", "Gamma Cyber Defense"),
    ]
    
    # Step 1: Register all organizations
    print("\n" + "="*60)
    print("STEP 1: ORGANIZATION REGISTRATION")
    print("="*60)
    
    for org in orgs:
        org.register()
    
    # Step 2: Get API tokens
    print("\n" + "="*60)
    print("STEP 2: OBTAINING API TOKENS")
    print("="*60)
    
    for org in orgs:
        org.get_token()
    
    # Step 3: List all organizations
    print("\n" + "="*60)
    print("STEP 3: LIST ALL ORGANIZATIONS")
    print("="*60)
    
    response = requests.get(f"{BASE_URL}/orgs/list")
    if response.status_code == 200:
        data = response.json()
        print(f"\nTotal organizations: {data['count']}")
        for o in data['organizations']:
            print(f"  • {o['org_name']} ({o['org_id']}) - Registered: {o['registered_at']}")
    
    # Step 4: Submit alerts from each organization
    print("\n" + "="*60)
    print("STEP 4: SUBMITTING ALERTS FROM MULTIPLE ORGS")
    print("="*60)
    
    alerts_data = [
        (orgs[0], {"alert_type": "malware", "severity": "high", "source": "endpoint"}, 85),
        (orgs[1], {"alert_type": "malware", "severity": "critical", "source": "network"}, 95),
        (orgs[2], {"alert_type": "phishing", "severity": "medium", "source": "email"}, 60),
        (orgs[0], {"alert_type": "ddos", "severity": "high", "source": "network"}, 78),
        (orgs[1], {"alert_type": "malware", "severity": "low", "source": "sandbox"}, 45),
    ]
    
    for org, alert_data, risk_score in alerts_data:
        org.submit_alert(alert_data, risk_score)
    
    # Step 5: Search for alerts
    print("\n" + "="*60)
    print("STEP 5: SEARCHING ALERTS BY TYPE")
    print("="*60)
    
    hmac_key = b"demo-hmac-beacon-key-32"
    malware_beacon = hmac_utils.compute_hmac("malware", key=hmac_key)
    
    print(f"\n🔍 Searching for 'malware' alerts...")
    response = requests.get(
        f"{BASE_URL}/alerts/search",
        params={"hmac_beacon": malware_beacon},
        headers=orgs[0].get_headers()
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"✓ Found {len(data['alerts'])} malware alerts")
        for alert in data['alerts']:
            print(f"  • Alert ID: {alert['alert_id']}")
    
    # Step 6: Aggregate risk scores
    print("\n" + "="*60)
    print("STEP 6: HOMOMORPHIC AGGREGATION")
    print("="*60)
    
    print("\n🔢 Computing aggregate statistics on encrypted risk scores...")
    response = requests.get(
        f"{BASE_URL}/alerts/aggregate",
        headers=orgs[0].get_headers()
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"✓ Aggregation complete!")
        print(f"  Total (encrypted): {data['total']['ciphertext'][:50]}...")
        print(f"  Average (encrypted): {data['average']['ciphertext'][:50]}...")
        print(f"\n  Note: These values are encrypted. Only authorized parties with")
        print(f"        the Paillier private key can decrypt them.")
    
    # Step 7: Show organization statistics
    print("\n" + "="*60)
    print("STEP 7: ORGANIZATION STATISTICS")
    print("="*60)
    
    for org in orgs:
        info = org.get_my_info()
        if info:
            print(f"\n{info['org_name']} ({info['org_id']}):")
            print(f"  Alerts submitted: {info['alerts_submitted']}")
    
    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60)
    print("\nThe system now supports multiple organizations, each with:")
    print("  ✓ Independent registration and authentication")
    print("  ✓ Secure alert submission with digital signatures")
    print("  ✓ Privacy-preserving search capabilities")
    print("  ✓ Homomorphic aggregation across all organizations")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
