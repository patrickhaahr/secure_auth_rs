USEFUL COMMANDS:
sqlx migrate add -r <description>
sqlx mirgate run

### admin
sqlite3 auth.db "SELECT account_id, is_admin, assigned_at FROM account_roles WHERE account_id = 'EWCs3zDkrg8aTYz1';"
