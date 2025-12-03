-- Email Security Analysis Database Schema
-- PostgreSQL database for storing email threat analysis results

-- Create database (run manually: createdb phishing_detection)

-- Emails table - stores incoming emails and final assessment
CREATE TABLE IF NOT EXISTS emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_uid VARCHAR(255) UNIQUE,  -- IMAP UID for n8n operations
    subject TEXT,
    sender VARCHAR(255),
    recipient VARCHAR(255),
    body TEXT,
    headers JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    received_at TIMESTAMP DEFAULT NOW(),
    final_risk_score FLOAT,
    final_threat_level VARCHAR(50),
    final_action VARCHAR(50),  -- QUARANTINE, ALLOW, PENDING
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Agent analyses table - stores individual agent results
CREATE TABLE IF NOT EXISTS agent_analyses (
    id SERIAL PRIMARY KEY,
    email_id UUID REFERENCES emails(id) ON DELETE CASCADE,
    agent_name VARCHAR(50) NOT NULL,  -- linguistic, technical, threat_intel, coordination
    risk_score FLOAT,
    threat_level VARCHAR(50),
    confidence FLOAT,
    indicators JSONB DEFAULT '[]',
    analysis TEXT,
    execution_time_ms INTEGER,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Coordination results table - stores final coordination agent output
CREATE TABLE IF NOT EXISTS coordination_results (
    id SERIAL PRIMARY KEY,
    email_id UUID REFERENCES emails(id) ON DELETE CASCADE,
    final_risk_score FLOAT,
    risk_level VARCHAR(50),
    aggregated_certainty VARCHAR(50),
    detailed_reasoning TEXT,
    uncertainty FLOAT,
    agent_contributions JSONB,
    explanation JSONB,
    recommended_actions JSONB,
    execution_time_ms INTEGER,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Chat sessions table - stores chat conversations about emails
CREATE TABLE IF NOT EXISTS chat_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id UUID REFERENCES emails(id) ON DELETE CASCADE,
    started_at TIMESTAMP DEFAULT NOW(),
    last_message_at TIMESTAMP DEFAULT NOW()
);

-- Chat messages table - stores individual chat messages
CREATE TABLE IF NOT EXISTS chat_messages (
    id SERIAL PRIMARY KEY,
    session_id UUID REFERENCES chat_sessions(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL,  -- user, assistant
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_emails_email_uid ON emails(email_uid);
CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_emails_final_action ON emails(final_action);
CREATE INDEX IF NOT EXISTS idx_agent_analyses_email_id ON agent_analyses(email_id);
CREATE INDEX IF NOT EXISTS idx_agent_analyses_agent_name ON agent_analyses(agent_name);
CREATE INDEX IF NOT EXISTS idx_coordination_email_id ON coordination_results(email_id);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_email_id ON chat_sessions(email_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);

-- Update trigger for emails.updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_emails_updated_at BEFORE UPDATE ON emails
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
