"""
Password hashing and verification using SHA-512 with salt
"""
import hashlib
import secrets
import hmac


def hash_password(password: str) -> str:
    """
    Hash a password using SHA-512 with a random salt.
    """
    # Generate 32 byte salt
    salt = secrets.token_hex(32)
    
    # Hash the password with the salt using SHA-512
    password_hash = hashlib.sha512((salt + password).encode('utf-8')).hexdigest()
    
    # Return salt and hash combined
    return f"{salt}${password_hash}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    """
    try:
        # Split the stored hash into salt and hash components
        salt, stored_hash = hashed_password.split('$')
        
        # Hash the provided password with the same salt
        password_hash = hashlib.sha512((salt + plain_password).encode('utf-8')).hexdigest()
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(password_hash, stored_hash)
    
    except (ValueError, AttributeError):
      
        return False
