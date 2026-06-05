# AdaptiveScan Database Schema

AdaptiveScan is designed for PostgreSQL in production with Alembic migrations. The current local implementation keeps a lightweight persistence boundary while modeling the commercial schema.

## Core Tables

### organizations

- `org_id`
- `name`
- `plan`
- `created_at`
- `status`
- `payment_provider_customer_id`

### workspaces

- `workspace_id`
- `org_id`
- `name`
- `default_allowlist`
- `created_at`

### auth_users

- `user_id`
- `organization_id`
- `email`
- `first_name`
- `last_name`
- `company_name`
- `role`
- `password_hash`
- `mfa_required`
- `created_at`
- `last_login_at`

### refresh_sessions

- `session_id`
- `user_id`
- `refresh_token_hash`
- `expires_at`
- `created_at`
- `revoked_at`

### otp_challenges

- `challenge_id`
- `email`
- `purpose`
- `code_hash`
- `expires_at`
- `consumed_at`

### api_keys

- `api_key_id`
- `workspace_id`
- `name`
- `key_hash`
- `scopes`
- `created_at`
- `last_used_at`

## ASM Tables

### assets

- `asset_id`
- `workspace_id`
- `asset_type`
- `name`
- `host`
- `owner`
- `tags`
- `criticality`
- `first_seen_at`
- `last_seen_at`

### asset_relationships

- `relationship_id`
- `source_asset_id`
- `target_asset_id`
- `relationship_type`
- `confidence`
- `evidence`

### asset_history

- `history_id`
- `asset_id`
- `event_type`
- `before`
- `after`
- `observed_at`

### exposure_events

- `event_id`
- `asset_id`
- `event_type`
- `severity`
- `score`
- `evidence`
- `observed_at`

## Findings And Reports

### scans

- `scan_id`
- `workspace_id`
- `target_url`
- `scan_profile`
- `status`
- `summary`
- `created_at`
- `completed_at`

### findings

- `finding_id`
- `scan_id`
- `asset_id`
- `title`
- `severity`
- `confidence`
- `status`
- `owner`
- `evidence`
- `remediation`

### finding_lifecycle

- `finding_id`
- `state`
- `owner`
- `sla_due_at`
- `updated_by`
- `updated_at`

### reports

- `report_id`
- `scan_id`
- `report_type`
- `artifact_url`
- `generated_at`

## Monitoring And Notifications

### monitoring_policies

- `policy_id`
- `workspace_id`
- `name`
- `cadence`
- `scope`
- `status`

### notification_channels

- `channel_id`
- `workspace_id`
- `type`
- `name`
- `config_secret_ref`
- `status`

### notification_rules

- `rule_id`
- `workspace_id`
- `name`
- `condition`
- `severity`
- `channel_ids`

## Audit And Billing

### audit_logs

- `event_id`
- `organization_id`
- `actor`
- `action`
- `target`
- `details`
- `created_at`

### subscriptions

- `subscription_id`
- `organization_id`
- `plan`
- `status`
- `trial_ends_at`
- `current_period_ends_at`

### usage_events

- `usage_event_id`
- `organization_id`
- `metric`
- `quantity`
- `metadata`
- `created_at`
