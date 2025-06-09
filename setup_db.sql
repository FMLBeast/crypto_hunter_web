-- Drop existing tables if they exist
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS analysis_files CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Create analysis_files table (simplified)
CREATE TABLE analysis_files (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    file_type VARCHAR(100),
    sha256_hash VARCHAR(64) UNIQUE NOT NULL,
    md5_hash VARCHAR(32),
    status VARCHAR(50) DEFAULT 'pending',
    is_encrypted BOOLEAN DEFAULT FALSE,
    contains_crypto BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by INTEGER REFERENCES users(id)
);

-- Create findings table (simplified)
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    file_id INTEGER REFERENCES analysis_files(id),
    finding_type VARCHAR(100) NOT NULL,
    confidence FLOAT DEFAULT 0.0,
    description TEXT,
    metadata JSON,
    created_at TIMESTAMP DEFAULT NOW(),
    created_by INTEGER REFERENCES users(id)
);

-- Create indexes for performance
CREATE INDEX idx_files_sha256 ON analysis_files(sha256_hash);
CREATE INDEX idx_files_status ON analysis_files(status);
CREATE INDEX idx_findings_type ON findings(finding_type);
CREATE INDEX idx_findings_confidence ON findings(confidence);

-- Insert admin user
INSERT INTO users (username, email, password_hash, is_admin, is_verified, created_at, updated_at) 
VALUES (
    'admin', 
    'admin@example.com', 
    '$2b$12$LQv3c1yqBwEHFqTh4Q8K.uEH0yJ02XFi7V2nk9L4o6yKZB1Q7ZQ7S',
    true, 
    true, 
    NOW(), 
    NOW()
) ON CONFLICT (username) DO NOTHING;
