CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE transactions (
    tx_id TEXT PRIMARY KEY,
    creditor_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE payees (
    tx_id TEXT NOT NULL,
    payee_id TEXT NOT NULL,
    share INTEGER NOT NULL,
    FOREIGN KEY (tx_id) REFERENCES transactions(tx_id) ON DELETE CASCADE
);

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE known_persons (
    user_id TEXT NOT NULL,
    known_user_id TEXT NOT NULL,
    PRIMARY KEY (user_id, known_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (known_user_id) REFERENCES users(id) ON DELETE CASCADE
);

ALTER TABLE payees ADD COLUMN paid BOOLEAN DEFAULT FALSE;