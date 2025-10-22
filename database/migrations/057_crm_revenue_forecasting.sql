-- Migration: 057_crm_revenue_forecasting
-- Description: AI-powered revenue forecasting with ±5% accuracy target
-- Feature: #10 in Phase 1 Sprint 1

CREATE TABLE IF NOT EXISTS crm_revenue_forecasts (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    forecast_period TEXT NOT NULL, -- 'Q1-2025', '2025-01', etc.
    forecast_type TEXT NOT NULL CHECK(forecast_type IN ('monthly', 'quarterly', 'annual')),

    -- Forecast Amounts
    forecasted_revenue REAL NOT NULL,
    confidence_interval_low REAL NOT NULL,
    confidence_interval_high REAL NOT NULL,
    confidence_level REAL CHECK(confidence_level >= 0 AND confidence_level <= 1.0),

    -- Pipeline Analysis
    pipeline_value REAL,
    weighted_pipeline REAL,
    deals_count INTEGER,
    expected_close_count INTEGER,

    -- AI Model
    model_version TEXT,
    prediction_factors TEXT,       -- JSON: key factors used in prediction

    -- Actual Results (for accuracy tracking)
    actual_revenue REAL,
    accuracy_percentage REAL,

    -- Metadata
    forecasted_at TEXT DEFAULT (datetime('now')),
    forecasted_by TEXT,

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE INDEX idx_crm_revenue_forecasts_period ON crm_revenue_forecasts(business_id, forecast_period);
