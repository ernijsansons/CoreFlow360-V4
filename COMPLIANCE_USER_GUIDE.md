# Compliance Management System - User Guide

**CoreFlow360 V4 - AI Agent Compliance Framework**

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Compliance Dashboard](#compliance-dashboard)
4. [Managing Guidelines](#managing-guidelines)
5. [Managing Policies](#managing-policies)
6. [Monitoring Violations](#monitoring-violations)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)
9. [API Reference](#api-reference)

---

## Introduction

### What is the Compliance Management System?

The Compliance Management System is a comprehensive framework that ensures all AI agents in CoreFlow360 V4 operate within defined rules and boundaries. It provides:

- **Guidelines**: Company-wide compliance rules for AI behavior
- **Policies**: Agent-specific restrictions and requirements
- **Violation Monitoring**: Real-time tracking of compliance breaches
- **Auto-Remediation**: Automatic content correction when possible

### Why Use Compliance Management?

✅ **Brand Protection**: Ensure AI agents maintain your brand voice and values
✅ **Data Security**: Prevent exposure of sensitive information (PII, financial data)
✅ **Quality Control**: Maintain minimum quality standards for AI outputs
✅ **Regulatory Compliance**: Meet industry-specific compliance requirements
✅ **Risk Mitigation**: Reduce liability through proactive monitoring

---

## Getting Started

### Accessing the Compliance Dashboard

1. **Navigate** to the Admin section in CoreFlow360
2. **Click** on "Compliance Management" in the sidebar
3. **View** the compliance dashboard overview

### Dashboard Overview

The dashboard displays four key tabs:

- **Overview**: Summary statistics and quick actions
- **Guidelines**: Company-wide compliance rules
- **Policies**: Agent-specific restrictions
- **Violations**: Real-time violation monitoring

---

## Compliance Dashboard

### Summary Cards

The dashboard displays four summary cards at the top:

#### Total Violations
- Shows total number of compliance violations across all time
- Updates in real-time

#### Unresolved Violations
- Displays violations that require attention
- Color-coded: Orange indicates issues need resolution

#### Critical Violations
- Shows high-priority violations
- Color-coded: Red indicates urgent attention required

#### Resolution Rate
- Percentage of violations that have been resolved
- Target: 80% or higher

### Quick Actions

The Overview tab provides quick access to:

1. **Create New Guideline** - Define a new compliance rule
2. **Configure Agent Policy** - Set agent-specific restrictions
3. **Review Violations** - View and resolve compliance breaches

### Compliance Health Status

The system displays real-time compliance health:

- **Healthy**: No critical issues, <5 unresolved violations
- **Warning**: 5-20 unresolved violations or 1+ high-priority issues
- **Critical**: 1+ critical violations require immediate attention

---

## Managing Guidelines

### What are Guidelines?

Guidelines are company-wide compliance rules that apply to all AI agents. They define:

- Acceptable tone and style
- Prohibited content and topics
- Data access boundaries
- Privacy and security requirements
- Brand voice standards

### Creating a Guideline

1. **Navigate** to the Guidelines tab
2. **Click** "Create Guideline" button
3. **Fill in the form**:

#### Guideline Name
```
Example: "Professional Tone Required"
```

#### Category
Choose from:
- **Tone & Style**: How agents should communicate
- **Content Restrictions**: Topics/words agents cannot mention
- **Data Boundaries**: What data agents can access
- **Privacy & Security**: PII protection rules
- **Brand Voice**: Company brand guidelines
- **Compliance Rules**: Legal/regulatory requirements
- **Escalation Triggers**: When to escalate to humans
- **Response Limits**: Output length/complexity limits

#### Severity
- **Low**: Minor issues, informational
- **Medium**: Moderate concern, should be addressed
- **High**: Significant issue, requires prompt action
- **Critical**: Severe violation, immediate action required

#### Enforcement Mode
- **Monitor**: Log violations but allow actions
- **Warn**: Show warnings but allow actions
- **Enforce**: Block non-compliant actions

#### Auto-Remediation
- **Enabled**: Automatically fix violations when possible
- **Disabled**: Block or warn without modification

#### Rules (JSON)
Define specific rules as JSON object:

**Example 1: Tone Requirements**
```json
{
  "requiredTone": "professional",
  "prohibitedTones": ["casual", "slang", "informal"],
  "allowedEmotions": ["helpful", "supportive"]
}
```

**Example 2: Content Restrictions**
```json
{
  "prohibitedWords": ["competitor", "rival", "alternative"],
  "prohibitedTopics": ["pricing_comparison", "competitor_criticism"],
  "allowedCompetitorMentions": false
}
```

**Example 3: Privacy Protection**
```json
{
  "piiProtection": true,
  "allowedPII": [],
  "redactEmails": true,
  "redactPhones": true,
  "redactSSN": true,
  "redactCreditCards": true
}
```

**Example 4: Brand Voice**
```json
{
  "tone": "professional",
  "characteristics": ["helpful", "expert", "supportive"],
  "doList": ["Use professional language", "Emphasize expertise", "Be supportive"],
  "dontList": ["Use slang", "Be overly casual", "Make guarantees"],
  "prohibitedWords": ["cheap", "hack", "tricks", "easy"]
}
```

4. **Click** "Create" to save the guideline

### Editing Guidelines

1. **Find** the guideline in the table
2. **Click** the edit icon (pencil)
3. **Modify** fields as needed
4. **Click** "Update" to save changes

### Deleting Guidelines

1. **Find** the guideline in the table
2. **Click** the delete icon (trash)
3. **Confirm** the deletion

⚠️ **Warning**: Deleting a guideline is permanent and will stop enforcement immediately.

### Filtering Guidelines

Use the filters to find specific guidelines:

- **Search**: Type keywords to search by name
- **Category Filter**: Show only specific category guidelines

---

## Managing Policies

### What are Policies?

Policies are agent-specific restrictions that control how individual AI agents operate. They define:

- Which capabilities an agent can use
- What data an agent can access
- Rate limits for agent requests
- Quality requirements for outputs
- Cost limits per request/day

### Creating a Policy

1. **Navigate** to the Policies tab
2. **Click** "Create Policy" button
3. **Fill in the form**:

#### Policy Name
```
Example: "Rate Limiting for Onboarding Agent"
```

#### Agent
Select which agent this policy applies to:
- Onboarding Agent
- Company Knowledge Agent
- Chat Support Agent
- Support Ticket Agent
- Knowledge Base Agent

#### Policy Type
Choose from:
- **Capability Restriction**: Limit which features agent can use
- **Data Access Control**: Restrict data access
- **Rate Limiting**: Control request frequency
- **Response Filtering**: Filter agent outputs
- **Escalation Rules**: When to escalate to humans
- **Quality Requirements**: Minimum quality standards
- **Cost Limits**: Maximum costs allowed

#### Enforcement Level
- **Monitor**: Log violations but allow
- **Warn**: Show warnings but allow
- **Enforce**: Block non-compliant actions

#### Policy Configuration (JSON)

**Example 1: Rate Limiting**
```json
{
  "requestsPerMinute": 10,
  "requestsPerHour": 100,
  "requestsPerDay": 1000
}
```

**Example 2: Capability Restriction**
```json
{
  "allowedCapabilities": ["data_import", "account_setup", "team_onboarding"],
  "blockedCapabilities": ["data_migration", "configuration_assistant"]
}
```

**Example 3: Data Access Control**
```json
{
  "allowedDataTypes": ["customers", "products", "orders"],
  "forbiddenDataTypes": ["financial_records", "personal_health", "credit_cards"]
}
```

**Example 4: Quality Requirements**
```json
{
  "minimumAccuracy": 0.85,
  "minimumCompleteness": 0.80,
  "minimumRelevance": 0.75
}
```

**Example 5: Cost Limits**
```json
{
  "maxCostPerRequest": 0.50,
  "maxHourlyCost": 5.00,
  "maxDailyCost": 50.00
}
```

4. **Click** "Create" to save the policy

### Editing Policies

Same process as guidelines - click edit icon, modify, and save.

### Deleting Policies

Same process as guidelines - click delete icon and confirm.

### Filtering Policies

- **Search**: Find policies by name
- **Agent Filter**: Show only policies for specific agent

---

## Monitoring Violations

### What are Violations?

Violations occur when an AI agent attempts an action that breaks a guideline or policy rule. The system:

1. **Detects** the violation (pre or post execution)
2. **Records** all details (agent, task, content, etc.)
3. **Takes Action** (block, modify, warn, or escalate)
4. **Notifies** admins for review

### Violation Types

**Content Violations**:
- **Prohibited Content**: Used forbidden words/topics
- **Tone Violation**: Wrong tone for brand
- **PII Exposure**: Exposed sensitive personal data

**Access Violations**:
- **Data Boundary Breach**: Accessed forbidden data
- **Unauthorized Capability**: Used blocked feature

**Performance Violations**:
- **Rate Limit Exceeded**: Too many requests
- **Cost Limit Exceeded**: Exceeded budget
- **Quality Below Threshold**: Output quality too low

**Process Violations**:
- **Escalation Required**: Trigger detected, needs human

### Viewing Violations

1. **Navigate** to the Violations tab
2. **View** the violations table
3. **Use filters** to narrow results:
   - **Search**: Find by agent, task, or type
   - **Type Filter**: Show specific violation types
   - **Severity Filter**: Show specific severity levels
   - **Status Filter**: Show resolved/unresolved only

### Violation Details

Click the eye icon to view full violation details:

#### Basic Information
- **Severity**: Critical, high, medium, or low
- **Type**: Specific violation type
- **Agent**: Which agent committed the violation
- **Task ID**: Unique identifier for the task
- **Occurred**: When the violation happened
- **Action Taken**: How the system responded

#### Content Information
- **Original Content**: What the agent tried to output
- **Remediated Content**: Auto-corrected version (if applicable)
- **Details**: JSON with violation-specific information

#### Resolution Information
- **Resolved**: Whether violation has been addressed
- **Resolved By**: Which admin resolved it
- **Resolved At**: When it was resolved
- **Resolution Notes**: Admin's explanation

### Resolving Violations

1. **Click** eye icon to view violation details
2. **Review** the violation information
3. **Determine** if it's a:
   - **True violation**: Legitimate compliance breach
   - **False positive**: System error, shouldn't be flagged
   - **Guideline issue**: Guideline needs adjustment
4. **Enter resolution notes** explaining your decision
5. **Click** "Mark as Resolved"

**Resolution Notes Examples**:

```
True Violation:
"Confirmed tone violation. Agent used casual language when professional tone required. Retrained agent on brand voice guidelines."

False Positive:
"False positive - content was appropriate in context. Customer specifically requested casual communication style. Adjusted guideline to allow case-by-case exceptions."

Guideline Needs Update:
"Violation technically correct but guideline too strict. Updated guideline to allow competitor mentions in defensive positioning only."
```

### Violation Alerts

The system provides automatic alerts for:

- **Critical Violations**: Immediate email/notification
- **Unresolved Count >5**: Daily summary
- **Unresolved Count >20**: Urgent notification

---

## Best Practices

### Guideline Best Practices

✅ **DO**:
- Start with monitor mode, then move to enforce after testing
- Use descriptive, clear names
- Document the "why" in guideline names
- Enable auto-remediation for content/PII violations
- Review guidelines quarterly
- Use templates for common scenarios

❌ **DON'T**:
- Create overlapping or conflicting guidelines
- Set everything to "critical" severity
- Use overly restrictive rules that block legitimate use
- Skip testing before enforcing
- Forget to communicate guidelines to team

### Policy Best Practices

✅ **DO**:
- Set reasonable rate limits based on actual usage
- Test policies in monitor mode first
- Document policy rationale
- Review policy effectiveness monthly
- Adjust based on violation patterns

❌ **DON'T**:
- Set rate limits too low for legitimate use
- Block capabilities without understanding impact
- Create policies that conflict with guidelines
- Ignore repeated violations from same agent
- Set cost limits too low for agent functionality

### Violation Management Best Practices

✅ **DO**:
- Review violations daily
- Resolve critical violations within 24 hours
- Document resolution decisions clearly
- Look for patterns in violations
- Adjust guidelines/policies based on learnings
- Celebrate compliance improvements

❌ **DON'T**:
- Ignore low-severity violations
- Resolve without investigation
- Create reactive guidelines for one-off issues
- Blame agents instead of improving rules
- Let unresolved count exceed 20

### Compliance Health Targets

| Metric | Target | Action if Below |
|--------|--------|-----------------|
| Resolution Rate | >80% | Review resolution process |
| Unresolved Count | <5 | Increase resolution cadence |
| Critical Violations | 0 | Immediate investigation |
| Guidelines Coverage | >80% active | Review inactive guidelines |
| Policy Coverage | >80% active | Review inactive policies |

---

## Troubleshooting

### Issue: Too Many False Positives

**Symptoms**: Many violations are marked as false positives

**Solutions**:
1. Review guideline rules for overreach
2. Use more specific prohibited words/topics
3. Add context-aware exceptions
4. Consider switching to "warn" mode
5. Improve rule specificity

### Issue: Violations Not Being Detected

**Symptoms**: Expected violations aren't showing up

**Solutions**:
1. Check guideline is active
2. Verify enforcement mode is "warn" or "enforce"
3. Review rule JSON syntax
4. Check agent ID in policy matches actual agent
5. Review compliance service logs

### Issue: Auto-Remediation Not Working

**Symptoms**: Content not being automatically corrected

**Solutions**:
1. Verify auto-remediation is enabled
2. Check enforcement mode is "enforce"
3. Confirm violation type supports auto-remediation
4. Review remediation logic for edge cases
5. Check for conflicting guidelines

### Issue: High Resolution Time

**Symptoms**: Violations stay unresolved for too long

**Solutions**:
1. Set up daily review process
2. Assign compliance manager role
3. Enable violation alerts
4. Prioritize critical/high severity first
5. Create resolution templates

### Issue: Agent Performance Degraded

**Symptoms**: Agent slower or less effective after policies applied

**Solutions**:
1. Review rate limit settings
2. Check if quality requirements too high
3. Verify capability restrictions aren't blocking key features
4. Test in monitor mode first
5. Adjust cost limits if needed

---

## API Reference

### Guidelines API

#### Create Guideline
```http
POST /api/v1/admin/compliance/guidelines
Content-Type: application/json

{
  "name": "Professional Tone Required",
  "category": "tone_and_style",
  "severity": "high",
  "rules": {
    "requiredTone": "professional",
    "prohibitedTones": ["casual"]
  },
  "enforcementMode": "enforce",
  "autoRemediation": true
}
```

#### List Guidelines
```http
GET /api/v1/admin/compliance/guidelines?category=tone_and_style&page=1&limit=20
```

#### Update Guideline
```http
PUT /api/v1/admin/compliance/guidelines/{guidelineId}
Content-Type: application/json

{
  "severity": "critical",
  "enforcementMode": "enforce"
}
```

#### Delete Guideline
```http
DELETE /api/v1/admin/compliance/guidelines/{guidelineId}
```

### Policies API

#### Create Policy
```http
POST /api/v1/admin/compliance/policies
Content-Type: application/json

{
  "policyName": "Rate Limiting for Chat Agent",
  "agentId": "chat-support-agent",
  "policyType": "rate_limiting",
  "policyConfig": {
    "requestsPerMinute": 10,
    "requestsPerHour": 100
  },
  "enforcementLevel": "enforce"
}
```

#### List Policies
```http
GET /api/v1/admin/compliance/policies?agentId=chat-support-agent
```

#### Update Policy
```http
PUT /api/v1/admin/compliance/policies/{policyId}
Content-Type: application/json

{
  "policyConfig": {
    "requestsPerMinute": 20
  }
}
```

#### Delete Policy
```http
DELETE /api/v1/admin/compliance/policies/{policyId}
```

### Violations API

#### List Violations
```http
GET /api/v1/admin/compliance/violations?severity=critical&resolved=false&page=1&limit=20
```

#### Get Violation Summary
```http
GET /api/v1/admin/compliance/violations/summary
```

#### Resolve Violation
```http
POST /api/v1/admin/compliance/violations/{violationId}/resolve
Content-Type: application/json

{
  "resolutionNotes": "Confirmed violation. Retrained agent on guidelines."
}
```

### Response Formats

#### Success Response
```json
{
  "success": true,
  "guidelineId": "guideline-123",
  "message": "Guideline created successfully"
}
```

#### Error Response
```json
{
  "success": false,
  "error": "Invalid category specified",
  "code": "VALIDATION_ERROR"
}
```

---

## Support & Resources

### Getting Help

- **Documentation**: [CoreFlow360 Docs](https://docs.coreflow360.com)
- **Support Email**: support@coreflow360.com
- **Community Forum**: [forum.coreflow360.com](https://forum.coreflow360.com)

### Training Resources

- **Video Tutorials**: Available in the Help Center
- **Webinars**: Monthly compliance management webinars
- **Best Practices Guide**: Download from Resources section

### Compliance Templates

Access pre-built guideline and policy templates:
1. Navigate to Guidelines/Policies tab
2. Click "Templates" button
3. Select template to apply
4. Customize for your needs

---

## Appendix

### Guideline Templates

**Professional Tone**
```json
{
  "name": "Professional Tone Required",
  "category": "tone_and_style",
  "severity": "high",
  "rules": {
    "requiredTone": "professional",
    "prohibitedTones": ["casual", "slang"]
  },
  "enforcementMode": "enforce",
  "autoRemediation": true
}
```

**No Competitor Mentions**
```json
{
  "name": "No Competitor Mentions",
  "category": "content_restrictions",
  "severity": "medium",
  "rules": {
    "prohibitedWords": ["competitor", "rival", "alternative"],
    "prohibitedTopics": ["competitor_comparison"]
  },
  "enforcementMode": "enforce",
  "autoRemediation": true
}
```

**PII Protection**
```json
{
  "name": "PII Protection",
  "category": "privacy_and_security",
  "severity": "critical",
  "rules": {
    "piiProtection": true,
    "redactEmails": true,
    "redactPhones": true,
    "redactSSN": true
  },
  "enforcementMode": "enforce",
  "autoRemediation": true
}
```

---

**Version**: 1.0.0
**Last Updated**: 2025-10-20
**Author**: CoreFlow360 Team
