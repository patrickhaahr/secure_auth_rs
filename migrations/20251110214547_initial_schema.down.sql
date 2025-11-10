-- Disable foreign keys for cleanup
PRAGMA foreign_keys = OFF;

-- Drop triggers
DROP TRIGGER IF EXISTS enforce_passkey_limit;

-- Drop indexes
DROP INDEX IF EXISTS idx_passkeys_credential_id;
DROP INDEX IF EXISTS idx_passkeys_account_id;
DROP INDEX IF EXISTS idx_cpr_hash;
DROP INDEX IF EXISTS idx_accounts_account_id;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS account_roles;
DROP TABLE IF EXISTS totp_secrets;
DROP TABLE IF EXISTS passkeys;
DROP TABLE IF EXISTS cpr_data;
DROP TABLE IF EXISTS accounts;

-- Re-enable foreign keys
PRAGMA foreign_keys = ON;
