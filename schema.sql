-- UHST Relay Server MySQL Schema

CREATE TABLE IF NOT EXISTS uhst_hosts (
    host_id VARCHAR(255) PRIMARY KEY,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS uhst_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    recipient_token_hash VARCHAR(64) NOT NULL,
    body TEXT NOT NULL,
    response_token TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_recipient (recipient_token_hash)
);
