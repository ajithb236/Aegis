-- Migration: Add encrypted private key storage
-- Run this to add encrypted key columns to organizations table

ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS encrypted_private_key TEXT,
ADD COLUMN IF NOT EXISTS key_salt TEXT,
ADD COLUMN IF NOT EXISTS key_nonce TEXT;

-- Note: Old plaintext keys in keys/ directory should be manually deleted after migration
