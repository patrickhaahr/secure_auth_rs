-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- Core account: UUID primary key, random AccountID for login
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,  -- UUID v4 (32 chars hex + 4 hyphens)
    account_id TEXT UNIQUE NOT NULL COLLATE NOCASE,  -- User-facing random ID
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CPR: mandatory, encrypted, globally unique (10 digits)
CREATE TABLE cpr_data (
    account_id TEXT PRIMARY KEY,
    cpr_encrypted BLOB NOT NULL,  -- Encrypted with age + random nonce
    cpr_hash TEXT NOT NULL UNIQUE,  -- HMAC-SHA256 for uniqueness check
    verified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- WebAuthn passkeys: max 5 per account
CREATE TABLE passkeys (
    id TEXT PRIMARY KEY,  -- UUID v4
    account_id TEXT NOT NULL,
    credential_id BLOB UNIQUE NOT NULL,  -- WebAuthn raw credential ID
    public_key BLOB NOT NULL,            -- COSE public key bytes
    sign_count INTEGER NOT NULL DEFAULT 0,
    aaguid BLOB NOT NULL,                -- 16-byte authenticator AAGUID
    attestation_type TEXT NOT NULL,      -- 'none', 'indirect', 'direct'
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- TOTP: optional, encrypted, one per account
CREATE TABLE totp_secrets (
    account_id TEXT PRIMARY KEY,
    secret_encrypted BLOB NOT NULL,  -- Encrypted base32 secret (32+ chars)
    algorithm TEXT NOT NULL DEFAULT 'SHA1' 
        CHECK(algorithm IN ('SHA1')),  -- SHA1 only for compatibility
    digits INTEGER NOT NULL DEFAULT 6 CHECK(digits = 6),
    period INTEGER NOT NULL DEFAULT 30 CHECK(period = 30),
    is_verified BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Admin flag: manually set via DB only (no HTTP endpoint)
CREATE TABLE account_roles (
    account_id TEXT PRIMARY KEY,
    is_admin BOOLEAN NOT NULL DEFAULT 0,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Indexes
CREATE UNIQUE INDEX idx_accounts_account_id ON accounts(account_id);
CREATE UNIQUE INDEX idx_cpr_hash ON cpr_data(cpr_hash);  -- Fast uniqueness
CREATE INDEX idx_passkeys_account_id ON passkeys(account_id);
CREATE INDEX idx_passkeys_credential_id ON passkeys(credential_id);

-- Enforce 5 passkey limit at DB level
CREATE TRIGGER enforce_passkey_limit 
BEFORE INSERT ON passkeys
FOR EACH ROW
BEGIN
    SELECT CASE 
        WHEN (SELECT COUNT(*) FROM passkeys WHERE account_id = NEW.account_id) >= 5
        THEN RAISE(ABORT, 'Maximum 5 passkeys per account exceeded')
    END;
END;

