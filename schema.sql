-- DocShield PostgreSQL Schema for Supabase
-- Run this script in the Supabase SQL Editor to initialize your database table and indexes.

CREATE TABLE IF NOT EXISTS document_scans (
    id SERIAL PRIMARY KEY,
    original_filename VARCHAR(255) NOT NULL,
    stored_path VARCHAR(512) NOT NULL,
    storage_backend VARCHAR(50) DEFAULT 'local',
    file_type VARCHAR(20) NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    is_duplicate BOOLEAN DEFAULT FALSE,
    duplicate_of_id INTEGER REFERENCES document_scans(id) ON DELETE SET NULL,
    extracted_text TEXT,
    extracted_name VARCHAR(255),
    extracted_dates TEXT,        -- JSON array of detected date strings
    extracted_doc_numbers TEXT,  -- JSON array of detected ID/document numbers
    pdf_metadata TEXT,           -- JSON object of PDF metadata & structure metrics
    fraud_indicators TEXT,       -- JSON array of rule-based warning objects
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'Low Risk',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index on SHA-256 hash for fast duplicate document lookup
CREATE INDEX IF NOT EXISTS idx_document_scans_sha256 ON document_scans(sha256_hash);

-- Index on risk_level and created_at for dashboard filtering and sorting
CREATE INDEX IF NOT EXISTS idx_document_scans_risk_level ON document_scans(risk_level);
CREATE INDEX IF NOT EXISTS idx_document_scans_created_at ON document_scans(created_at DESC);

-- Recommended: Enable Row Level Security (RLS) so public anon keys cannot read private scan results directly
ALTER TABLE document_scans ENABLE ROW LEVEL SECURITY;
