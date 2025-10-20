-- Migration: 059_crm_duplicate_detection
-- Description: Fuzzy matching and duplicate detection with merge suggestions
-- Feature: #12 in Phase 1 Sprint 1

CREATE TABLE IF NOT EXISTS crm_duplicate_pairs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'company', 'lead')),
    entity_1_id TEXT NOT NULL,
    entity_2_id TEXT NOT NULL,

    -- Matching Scores
    overall_confidence REAL NOT NULL CHECK(overall_confidence >= 0 AND overall_confidence <= 1.0),
    name_similarity REAL,
    email_similarity REAL,
    phone_similarity REAL,
    company_similarity REAL,

    -- Matching Details
    matching_fields TEXT,          -- JSON array of fields that matched
    differing_fields TEXT,         -- JSON array of fields that differ

    -- Resolution
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'merged', 'not_duplicate', 'ignored')),
    merged_into_id TEXT,
    resolved_at TEXT,
    resolved_by_user_id TEXT,

    -- Metadata
    detected_at TEXT DEFAULT (datetime('now')),
    detection_method TEXT DEFAULT 'fuzzy_match',

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (resolved_by_user_id) REFERENCES users(id),
    UNIQUE(entity_1_id, entity_2_id)
);

CREATE INDEX idx_crm_duplicate_pairs_status ON crm_duplicate_pairs(business_id, status, overall_confidence DESC);
CREATE INDEX idx_crm_duplicate_pairs_entity1 ON crm_duplicate_pairs(entity_1_id);
CREATE INDEX idx_crm_duplicate_pairs_entity2 ON crm_duplicate_pairs(entity_2_id);
