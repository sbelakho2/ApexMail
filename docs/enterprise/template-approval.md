# Template Approval Workflows

ApexMail's template approval system enables teams to maintain brand consistency, ensure compliance, and prevent unauthorized content from being sent.

## Overview

Template approval workflows provide:

- **Multi-Stage Reviews** - Sequential approval from multiple stakeholders
- **Role-Based Approvers** - Different approval chains by template type
- **Version Control** - Track all template changes and revisions
- **Audit Trail** - Complete history of approvals and rejections
- **Automated Compliance** - Built-in checks for regulatory requirements

## Workflow Configuration

### Create Approval Workflow

```bash
curl -X POST https://enterprise.apexmail.ee/template-workflows \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "acc_xxx",
    "name": "Marketing Template Review",
    "stages": [
      {
        "name": "content_review",
        "approvers": [
          {"type": "role", "value": "content_manager"},
          {"type": "user", "value": "user_abc123"}
        ],
        "requiredApprovals": 1,
        "autoApproveAfter": null
      },
      {
        "name": "legal_review",
        "approvers": [
          {"type": "role", "value": "legal_team"}
        ],
        "requiredApprovals": 1,
        "autoApproveAfter": 72
      },
      {
        "name": "final_approval",
        "approvers": [
          {"type": "role", "value": "marketing_director"}
        ],
        "requiredApprovals": 1,
        "autoApproveAfter": null
      }
    ],
    "notifyOnSubmission": true,
    "notifyOnApproval": true,
    "notifyOnRejection": true
  }'
```

### Response

```json
{
  "workflow": {
    "id": "wf_marketing_review",
    "name": "Marketing Template Review",
    "stages": [...],
    "status": "active",
    "createdAt": "2024-01-15T10:30:00Z"
  }
}
```

## Approval Stages

### Stage Types

| Stage | Purpose | Typical Approvers |
|-------|---------|-------------------|
| Content Review | Grammar, messaging accuracy | Content Manager |
| Brand Review | Visual consistency | Brand Team |
| Legal Review | Compliance, disclaimers | Legal Team |
| Technical Review | Template code, personalization | Dev Team |
| Final Approval | Business sign-off | Department Head |

### Stage Configuration Options

```json
{
  "stage": {
    "name": "legal_review",
    "approvers": [
      {"type": "role", "value": "legal_team"},
      {"type": "user", "value": "user_legal_head"}
    ],
    "requiredApprovals": 1,
    "autoApproveAfter": 72,
    "escalateTo": "user_cto",
    "escalateAfter": 48,
    "requireComment": true,
    "checklistItems": [
      "Unsubscribe link present",
      "Physical address included",
      "No misleading subject line"
    ]
  }
}
```

## Submitting Templates for Approval

### Submit Template

```bash
curl -X POST https://enterprise.apexmail.ee/templates/{template_id}/submit \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "workflowId": "wf_marketing_review",
    "notes": "Q1 promotion campaign template",
    "priority": "normal",
    "requestedBy": "user_marketing_lead"
  }'
```

### Response

```json
{
  "submission": {
    "id": "sub_xyz789",
    "templateId": "tmpl_abc123",
    "workflowId": "wf_marketing_review",
    "status": "pending",
    "currentStage": "content_review",
    "submittedBy": "user_marketing_lead",
    "submittedAt": "2024-01-15T10:30:00Z",
    "timeline": {
      "content_review": {
        "status": "pending",
        "dueDate": "2024-01-16T10:30:00Z"
      },
      "legal_review": {
        "status": "not_started"
      },
      "final_approval": {
        "status": "not_started"
      }
    }
  }
}
```

## Processing Approvals

### Approve Template

```bash
curl -X POST https://enterprise.apexmail.ee/templates/approve \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "submissionId": "sub_xyz789",
    "approverId": "user_abc123",
    "decision": "approved",
    "comment": "Content looks good. Approved for legal review.",
    "checklist": {
      "Unsubscribe link present": true,
      "Physical address included": true,
      "No misleading subject line": true
    }
  }'
```

### Reject Template

```bash
curl -X POST https://enterprise.apexmail.ee/templates/approve \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "submissionId": "sub_xyz789",
    "approverId": "user_legal_head",
    "decision": "rejected",
    "comment": "Missing required disclaimer for promotional content.",
    "rejectionReason": "compliance_issue",
    "requiredChanges": [
      "Add FTC disclaimer for promotional content",
      "Include opt-out instructions"
    ]
  }'
```

## Template Versioning

### Version History

```bash
curl https://enterprise.apexmail.ee/templates/{template_id}/versions \
  -H "X-API-Key: YOUR_API_KEY"
```

Response:
```json
{
  "versions": [
    {
      "version": 3,
      "status": "approved",
      "approvedAt": "2024-01-15T14:30:00Z",
      "approvedBy": "user_marketing_director",
      "changes": "Updated header image, fixed CTA button"
    },
    {
      "version": 2,
      "status": "rejected",
      "rejectedAt": "2024-01-14T16:00:00Z",
      "rejectedBy": "user_legal_head",
      "reason": "Missing disclaimer"
    },
    {
      "version": 1,
      "status": "superseded",
      "createdAt": "2024-01-13T10:00:00Z",
      "createdBy": "user_designer"
    }
  ]
}
```

### Compare Versions

```bash
curl https://enterprise.apexmail.ee/templates/{template_id}/compare \
  -H "X-API-Key: YOUR_API_KEY" \
  -G -d "v1=2" -d "v2=3"
```

## Approval Status & Tracking

### Check Submission Status

```bash
curl https://enterprise.apexmail.ee/templates/submissions/{submission_id} \
  -H "X-API-Key: YOUR_API_KEY"
```

Response:
```json
{
  "submission": {
    "id": "sub_xyz789",
    "status": "in_review",
    "currentStage": "legal_review",
    "progress": {
      "content_review": {
        "status": "approved",
        "approvedBy": "user_content_mgr",
        "approvedAt": "2024-01-15T14:00:00Z",
        "comment": "Looks great!"
      },
      "legal_review": {
        "status": "pending",
        "assignedTo": ["user_legal_head"],
        "dueDate": "2024-01-17T14:00:00Z",
        "reminders": 1
      },
      "final_approval": {
        "status": "not_started"
      }
    },
    "audit": [
      {
        "action": "submitted",
        "user": "user_marketing_lead",
        "timestamp": "2024-01-15T10:30:00Z"
      },
      {
        "action": "approved",
        "stage": "content_review",
        "user": "user_content_mgr",
        "timestamp": "2024-01-15T14:00:00Z"
      }
    ]
  }
}
```

### List Pending Approvals

```bash
curl https://enterprise.apexmail.ee/templates/submissions/pending \
  -H "X-API-Key: YOUR_API_KEY" \
  -G -d "approverId=user_legal_head"
```

## Automated Checks

### Built-in Compliance Checks

Configure automated checks before human review:

```json
{
  "automatedChecks": {
    "enabled": true,
    "checks": [
      {
        "name": "unsubscribe_link",
        "required": true,
        "blockOnFail": true
      },
      {
        "name": "physical_address",
        "required": true,
        "blockOnFail": false
      },
      {
        "name": "spam_score",
        "threshold": 3.0,
        "blockOnFail": true
      },
      {
        "name": "link_validation",
        "checkBrokenLinks": true,
        "blockOnFail": false
      },
      {
        "name": "brand_assets",
        "verifyApprovedAssets": true,
        "blockOnFail": false
      }
    ]
  }
}
```

### Check Results

```json
{
  "automatedChecks": {
    "passed": false,
    "results": [
      {
        "check": "unsubscribe_link",
        "status": "passed",
        "details": "Found at footer"
      },
      {
        "check": "spam_score",
        "status": "failed",
        "score": 4.2,
        "issues": [
          "All caps in subject line",
          "Multiple exclamation marks"
        ]
      }
    ]
  }
}
```

## Notifications

### Configure Notifications

```json
{
  "notifications": {
    "channels": ["email", "slack", "webhook"],
    "events": {
      "submission_created": true,
      "approval_required": true,
      "stage_approved": true,
      "template_approved": true,
      "template_rejected": true,
      "escalation": true,
      "reminder": true
    },
    "slack": {
      "webhookUrl": "https://hooks.slack.com/...",
      "channel": "#template-approvals"
    },
    "webhook": {
      "url": "https://your-system.com/webhooks/templates",
      "headers": {"Authorization": "Bearer xxx"}
    }
  }
}
```

## Escalation

### Configure Escalation

```json
{
  "escalation": {
    "enabled": true,
    "rules": [
      {
        "condition": "pending_hours > 24",
        "action": "reminder"
      },
      {
        "condition": "pending_hours > 48",
        "action": "escalate",
        "escalateTo": "user_manager"
      },
      {
        "condition": "pending_hours > 72",
        "action": "auto_approve",
        "notify": ["user_admin"]
      }
    ]
  }
}
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/template-workflows` | POST | Create workflow |
| `/template-workflows` | GET | List workflows |
| `/template-workflows/{id}` | GET | Get workflow |
| `/template-workflows/{id}` | PUT | Update workflow |
| `/templates/{id}/submit` | POST | Submit for approval |
| `/templates/approve` | POST | Process approval/rejection |
| `/templates/submissions` | GET | List submissions |
| `/templates/submissions/{id}` | GET | Get submission details |
| `/templates/submissions/pending` | GET | List pending approvals |
| `/templates/{id}/versions` | GET | Get version history |
| `/templates/{id}/compare` | GET | Compare versions |

## Best Practices

1. **Clear Ownership** - Assign specific approvers to each stage
2. **Reasonable SLAs** - Set realistic timeframes for each review stage
3. **Detailed Comments** - Require comments for rejections
4. **Checklist Items** - Use checklists to ensure consistent reviews
5. **Automated Checks First** - Catch obvious issues before human review
6. **Version Everything** - Maintain full history for compliance audits
