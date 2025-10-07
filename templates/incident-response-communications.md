# Incident Response Communication Templates

## Overview

Pre-approved communication templates for handling production incidents, outages, and service degradations with customers.

---

## 1. Incident Classification

### Severity Levels

**P0 - Critical (Service Down)**
- Complete service outage
- Data loss or corruption
- Security breach
- Impact: All customers
- Response: Immediate
- Communication: Within 15 minutes

**P1 - Major (Degraded Service)**
- Significant feature unavailable
- Performance severely degraded
- Impact: Most customers
- Response: Within 30 minutes
- Communication: Within 1 hour

**P2 - Moderate (Limited Impact)**
- Minor feature issues
- Intermittent errors
- Impact: Some customers
- Response: Within 2 hours
- Communication: Within 4 hours

**P3 - Low (Cosmetic/Minor)**
- UI glitches
- Non-critical bugs
- Impact: Minimal
- Response: Next business day
- Communication: Optional

---

## 2. P0 Critical Incident Templates

### Initial Notification (Within 15 min)

**Subject:** [URGENT] Service Disruption - CoreFlow360 V4

```
Hi [Customer Name],

We're currently experiencing a service disruption affecting CoreFlow360 V4.

WHAT'S HAPPENING:
[Brief description of the issue - keep it simple]

IMPACT:
[What features/functionality are affected]

WHAT WE'RE DOING:
Our engineering team is actively investigating and working on a resolution. We will provide updates every 30 minutes until the issue is resolved.

NEXT UPDATE:
[Time of next update]

We apologize for the inconvenience and appreciate your patience.

- CoreFlow360 Team

Track live updates: https://status.coreflow360.com
```

### Progress Update (Every 30 min)

**Subject:** [UPDATE] Service Disruption - CoreFlow360 V4

```
Hi [Customer Name],

UPDATE as of [Time]:

PROGRESS:
[What we've discovered and what actions we've taken]

CURRENT STATUS:
[Still investigating / Fix deployed / Partial restoration / etc.]

ESTIMATED RESOLUTION:
[Honest estimate or "Still investigating"]

NEXT UPDATE:
[Time of next update - max 30 min]

Thank you for your continued patience.

- CoreFlow360 Team

Track live updates: https://status.coreflow360.com
```

### Resolution Notice

**Subject:** [RESOLVED] Service Restored - CoreFlow360 V4

```
Hi [Customer Name],

GOOD NEWS: The service disruption has been resolved as of [Time].

WHAT HAPPENED:
[Clear, honest explanation of the root cause]

WHAT WE FIXED:
[Technical fix implemented]

VERIFICATION:
All systems are now operating normally. We're continuing to monitor closely.

PREVENTING FUTURE INCIDENTS:
[Brief mention of preventive measures being implemented]

POST-INCIDENT REVIEW:
We will conduct a thorough post-mortem and share findings within 48 hours.

COMPENSATION (if applicable):
[Service credit details or other compensation]

We sincerely apologize for this disruption and thank you for your patience.

If you continue to experience issues, please contact support@coreflow360.com

- CoreFlow360 Team
```

### Post-Incident Report (Within 48 hours)

**Subject:** Post-Incident Report: [Date] Service Disruption

```
Hi [Customer Name],

Following the service disruption on [Date], we want to share a detailed post-incident report.

INCIDENT SUMMARY:
- Duration: [Start time] to [End time] ([X] hours, [Y] minutes)
- Impact: [Number/percentage] of customers affected
- Root Cause: [Detailed technical explanation]

TIMELINE:
[HH:MM] - Incident began
[HH:MM] - First alert triggered
[HH:MM] - Investigation started
[HH:MM] - Root cause identified
[HH:MM] - Fix deployed
[HH:MM] - Service restored
[HH:MM] - Verified resolution

WHAT WE'RE DOING TO PREVENT THIS:
1. [Specific improvement #1]
2. [Specific improvement #2]
3. [Specific improvement #3]

COMPENSATION:
[Service credit details, if applicable]

We take reliability extremely seriously and are committed to earning back your trust.

Questions? Reply to this email or contact support@coreflow360.com

- CoreFlow360 Leadership Team
```

---

## 3. P1 Major Incident Templates

### Initial Notification (Within 1 hour)

**Subject:** Service Advisory - [Feature/Component] Issue

```
Hi [Customer Name],

We're currently experiencing issues with [specific feature/component] in CoreFlow360 V4.

IMPACT:
[Specific features affected]
[Workaround available, if any]

STATUS:
Our team is actively investigating and working on a fix.

WORKAROUND (if available):
[Step-by-step workaround instructions]

We'll provide an update within 2 hours or sooner if resolved.

- CoreFlow360 Team
```

### Resolution Notice

**Subject:** [RESOLVED] Service Advisory - [Feature/Component] Restored

```
Hi [Customer Name],

The issues with [feature/component] have been resolved as of [Time].

WHAT WAS FIXED:
[Brief explanation]

IMPACT DURATION:
[Start time] to [End time]

All functionality should now be working normally. If you continue to experience issues, please contact support.

Thank you for your patience.

- CoreFlow360 Team
```

---

## 4. Scheduled Maintenance Templates

### 7-Day Advance Notice

**Subject:** Scheduled Maintenance - [Date] at [Time]

```
Hi [Customer Name],

We're scheduling planned maintenance to improve CoreFlow360 V4's performance and reliability.

WHEN:
[Date] at [Time] [Timezone]
Expected duration: [X] hours

WHAT TO EXPECT:
[List of features that will be unavailable]
[List of features that will continue working]

WHY WE'RE DOING THIS:
[Brief explanation of improvements being made]

WHAT YOU SHOULD DO:
[Any preparation steps customers should take]
- Save your work before maintenance begins
- Plan critical operations outside maintenance window
- [Other recommendations]

ALTERNATIVE (if available):
[API access, mobile app, etc. if still functional]

We'll send a reminder 24 hours before maintenance begins.

Questions? Contact support@coreflow360.com

- CoreFlow360 Team
```

### 24-Hour Reminder

**Subject:** REMINDER: Maintenance Tomorrow - [Date] at [Time]

```
Hi [Customer Name],

This is a reminder that scheduled maintenance begins in 24 hours.

WHEN:
[Date] at [Time] [Timezone]

DURATION:
Approximately [X] hours

IMPACT:
[Brief list of affected features]

PREPARATION:
Please ensure all critical work is saved before maintenance begins.

We'll notify you when maintenance is complete.

- CoreFlow360 Team
```

### Maintenance Complete

**Subject:** Maintenance Complete - CoreFlow360 V4 Fully Restored

```
Hi [Customer Name],

Good news! Scheduled maintenance completed [on time / 30 minutes early / with a 15-minute delay].

COMPLETED:
All planned updates and improvements have been successfully deployed.

NEW IN THIS UPDATE:
[Brief list of improvements, if user-visible]

VERIFICATION:
All systems are operating normally. We're monitoring closely.

Thank you for your patience during this maintenance window.

If you experience any issues, please contact support@coreflow360.com

- CoreFlow360 Team
```

---

## 5. Security Incident Templates

### Security Incident Notification

**Subject:** [URGENT] Security Notice - Action Required

```
Hi [Customer Name],

We're writing to inform you of a security incident affecting CoreFlow360 V4.

WHAT HAPPENED:
[Clear, honest description of the security event]

WHAT DATA WAS AFFECTED:
[Specific types of data - be transparent]

WHAT WE'VE DONE:
1. [Immediate containment actions]
2. [Investigation steps]
3. [Security improvements deployed]

WHAT YOU SHOULD DO:
1. [Specific actions customers should take]
2. Reset your password: [Link]
3. Review your account activity: [Link]
4. Enable 2FA if not already active: [Link]

ONGOING INVESTIGATION:
We're working with [security firm/authorities] to fully investigate this incident.

NEXT STEPS:
- We'll provide updates every [X] hours
- Full incident report within [Y] days
- [Compensation/support offerings]

We take security extremely seriously and deeply apologize for this incident.

Security questions: security@coreflow360.com
Urgent support: [Phone number]

- CoreFlow360 Security Team
```

---

## 6. Data Loss/Corruption Templates

### Data Issue Notification

**Subject:** [URGENT] Data Issue Notification - Action Required

```
Hi [Customer Name],

We've identified a data issue affecting your account in CoreFlow360 V4.

WHAT HAPPENED:
[Clear explanation of the data issue]

AFFECTED DATA:
[Specific data types/timeframes affected]

IMPACT TO YOU:
[Specific impact on customer's business]

WHAT WE'RE DOING:
1. Data recovery in progress from [backup timestamp]
2. [Other recovery steps]

WHAT YOU SHOULD DO:
1. [If applicable] Stop making changes to affected areas
2. Review your recent data exports (if available)
3. Contact us immediately if you have local backups: support@coreflow360.com

RECOVERY TIMELINE:
Expected completion: [Honest estimate]

We're treating this as our highest priority and will provide updates every hour.

Next update: [Time]

We sincerely apologize for this issue.

- CoreFlow360 Team
Emergency hotline: [Phone number]
```

### Data Recovery Complete

**Subject:** Data Recovery Complete - Verification Required

```
Hi [Customer Name],

Data recovery for your account has been completed.

RECOVERED DATA:
[Description of recovered data]
Restored from backup: [Timestamp]

PLEASE VERIFY:
We strongly recommend you verify your data:
1. Check [critical data points]
2. Review [specific sections]
3. Confirm [important records]

WHAT WAS NOT RECOVERABLE:
[If applicable, be honest about any data that couldn't be recovered]

COMPENSATION:
[Service credits, extended trial, etc.]

PREVENTING FUTURE INCIDENTS:
[Specific improvements being implemented]

If you notice any discrepancies, please contact us immediately at support@coreflow360.com

We deeply apologize for this incident.

- CoreFlow360 Team
```

---

## 7. Performance Degradation Templates

### Performance Issue Notice

**Subject:** Service Advisory - Performance Degradation

```
Hi [Customer Name],

We're currently experiencing slower than normal response times in CoreFlow360 V4.

IMPACT:
- Page load times: [X]% slower than normal
- API responses: Delayed by [Y] seconds
- Affected features: [List]

CAUSE:
[Brief explanation if known]

WHAT WE'RE DOING:
Scaling up infrastructure and optimizing performance.

ESTIMATED RESOLUTION:
[Honest estimate]

The service remains fully functional, just slower than normal.

We'll update you within [X] hours.

- CoreFlow360 Team
```

---

## 8. Third-Party Service Outage Templates

### Dependency Outage Notice

**Subject:** Service Impact - Third-Party Provider Issue

```
Hi [Customer Name],

We're experiencing service disruption due to an outage at [Third-Party Provider].

AFFECTED FEATURES:
[List of features that depend on the third-party service]

UNAFFECTED FEATURES:
[List of features still working normally]

WHAT WE KNOW:
[Third-Party Provider] is experiencing [brief description]. Their status page: [Link]

WORKAROUND (if available):
[Alternative approaches]

WHAT WE'RE DOING:
- Monitoring the third-party resolution
- Implementing temporary workarounds where possible
- Exploring alternative providers for future resilience

We'll update you as soon as the third-party service is restored.

- CoreFlow360 Team
```

---

## 9. Communication Channels

### Status Page Updates

**Every incident should also be posted to:**
- Status page: https://status.coreflow360.com
- Twitter: @CoreFlow360Status
- In-app banner notification

**Status page template:**
```markdown
[STATUS_ICON] [INCIDENT_TITLE]

**Posted:** [Timestamp]
**Impact:** [Severity]

[Description]

**Updates:**
- [Latest timestamp]: [Update message]
- [Earlier timestamp]: [Earlier update]

**Affected Components:**
- [Component 1]: [Status]
- [Component 2]: [Status]
```

### Support Response Template

**For individual support tickets during incidents:**

```
Hi [Customer Name],

Thank you for contacting us. We're aware of the issue you're experiencing - it's related to the ongoing incident affecting [component/feature].

INCIDENT STATUS:
[Link to status page or brief update]

ESTIMATED RESOLUTION:
[Honest estimate]

YOUR TICKET:
We've logged your ticket (#[NUMBER]) and will follow up with you personally once the incident is resolved to ensure everything is working correctly for you.

URGENT NEEDS:
If this is blocking critical business operations, please reply with details and we'll explore priority workarounds.

Thank you for your patience.

- CoreFlow360 Support Team
```

---

## 10. Internal Incident Communication

### Engineering Team Incident Alert

**Slack/Teams message template:**

```
🚨 INCIDENT DETECTED 🚨

Severity: P[0/1/2/3]
Component: [Name]
Started: [Timestamp]
Impact: [Brief description]

Incident Commander: @[Name]
War Room: #incident-[YYYY-MM-DD]

Next update: [Time]

[Link to runbook]
[Link to monitoring dashboard]
[Link to status page]
```

### Incident Resolution Announcement

```
✅ INCIDENT RESOLVED

Duration: [X hours, Y minutes]
Impact: [Brief summary]
Root cause: [Brief explanation]

Post-mortem scheduled for: [Date/Time]

Thanks to the incident response team:
- [Team member 1]
- [Team member 2]
- [etc.]

Full post-mortem will be shared in #engineering-updates
```

---

## 11. Escalation Procedures

### When to Escalate

**To CEO/CTO:**
- P0 incidents lasting >2 hours
- Security breaches
- Data loss incidents
- Incidents affecting >50% of customers

**To Legal:**
- Security breaches involving PII
- Potential GDPR violations
- Data loss of customer data

**To PR/Communications:**
- Incidents requiring public statement
- Media inquiries about incidents
- Social media crisis situations

---

## 12. Compensation Guidelines

### Service Credits

**P0 Incidents:**
- <2 hours: 10% monthly credit
- 2-6 hours: 25% monthly credit
- >6 hours: 50% monthly credit
- >24 hours: 100% monthly credit

**P1 Incidents:**
- <6 hours: 5% monthly credit
- >6 hours: 10% monthly credit

**Data Loss:**
- Minimum 100% monthly credit
- Consider additional compensation based on business impact

**Security Breaches:**
- 100% monthly credit + 3 months free service
- Dedicated security review and support

---

## 13. Template Usage Checklist

### During Incident Response

- [ ] Classify incident severity (P0-P3)
- [ ] Identify incident commander
- [ ] Start war room communication channel
- [ ] Send initial notification (within SLA time)
- [ ] Update status page
- [ ] Post to social media (if P0/P1)
- [ ] Send progress updates per schedule
- [ ] Document all actions in incident log
- [ ] Send resolution notice
- [ ] Schedule post-mortem (within 48h)
- [ ] Calculate and apply service credits
- [ ] Send post-incident report

---

## Quick Reference

| Severity | Response Time | First Communication | Update Frequency |
|----------|---------------|---------------------|------------------|
| P0       | Immediate     | 15 minutes          | Every 30 min     |
| P1       | 30 minutes    | 1 hour              | Every 2 hours    |
| P2       | 2 hours       | 4 hours             | Every 4 hours    |
| P3       | Next day      | Optional            | As needed        |

---

**Remember:** Clear, honest, timely communication builds trust even during incidents. Never hide the truth or make promises you can't keep.
