-- QuantumShield Database Schema
-- Run this script to initialize a new production database server.

CREATE DATABASE IF NOT EXISTS quantumshield;
USE quantumshield;

-- Table: scans
CREATE TABLE IF NOT EXISTS scans (
    id VARCHAR(36) PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    timestamp DATETIME NOT NULL,
    status VARCHAR(50) NOT NULL,
    total_assets INT DEFAULT 0,
    quantum_safe INT DEFAULT 0,
    quantum_vulnerable INT DEFAULT 0,
    critical_findings INT DEFAULT 0,
    compliance_score INT DEFAULT 0,
    report_json LONGTEXT,
    is_encrypted BOOLEAN DEFAULT FALSE,
    INDEX idx_target (target),
    INDEX idx_timestamp (timestamp)
);

-- Table: cbom_reports
CREATE TABLE IF NOT EXISTS cbom_reports (
    scan_id VARCHAR(36) PRIMARY KEY,
    cbom_json LONGTEXT NOT NULL,
    is_encrypted BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Table: users
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(150) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    reset_token VARCHAR(255) UNIQUE,
    token_expiry DATETIME
);

-- Default Admin User 
-- Password is 'admin123' (Argon2 hash). It is HIGHLY RECOMMENDED to change this immediately or use the invite system.
INSERT IGNORE INTO users (id, username, email, password_hash, role) 
VALUES (
    uuid(), 
    'admin', 
    'admin@localhost',
    '$argon2id$v=19$m=65536,t=3,p=4$zB4i8GkR8wT7M4R2mU5RSw$K8z7Y8/0iFw/R/5nO/Tz9YgK/Y8W/3/y/8X/4/v/2/Q', 
    'Admin'
);
