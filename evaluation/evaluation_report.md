# Evaluation Report — Ghost Data Still Exists

HackerRank Orchestrate (October 2026)  
Autonomous AI-Powered Deletion-Audit Agent

---

## 1. Executive Summary

This evaluation report details the benchmark results, metrics, failure analysis, and validation cases for our deletion-audit agent built for the **Ghost Data Still Exists** challenge. The solution reconstructs user identity histories across historical audits, monitors global system activity streams, parses multimodal evidence (SQL replicas, JSON snapshots, image OCR, structured logs, and service exports), enforces corporate deletion policy rules (`deletion_rules.csv`), and produces fully verified audit decisions and remediation plans.

The evaluation was validated on the public benchmark of 32 verified cases in `dataset/sample_deletion_requests.csv` against `dataset/sample_output.csv` and subsequently executed across the full 518-case challenge dataset.

---

## 2. Quantitative Accuracy Metrics

### 2.1 Benchmark Results (32 Public Requests)

| Metric | Score | Detail |
|---|---|---|
| **Case-Level Deletion-Status Accuracy** | **100.00%** | **32 / 32** exact status matches (`COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`) |
| **Exact Step Sequence Accuracy** | **81.25%** | **26 / 32** identical ordered step sequences across all phases |
| **Step-Level Precision** | **97.38%** | **186 / 191** valid predicted steps |
| **Step-Level Recall** | **96.37%** | **186 / 193** gold steps recovered |
| **Step-Level F1 Score** | **96.88%** | Harmonized step-level accuracy |

### 2.2 Field-Level Accuracy Breakdown

Each predicted step was evaluated field-by-field across the six contract attributes:

| Field | Accuracy | Matched / Compared | Description |
|---|---|---|---|
| **`phase`** | **100.00%** | 191 / 191 | Strict monotonic ordering (`FINDING` $\to$ `REMEDIATION` $\to$ `VERIFICATION`) |
| **`evidence_id`** | **99.48%** | 190 / 191 | Correct grounded evidence citations for findings and complete-case verifications; empty for proposed remediation |
| **`system_id`** | **97.91%** | 187 / 191 | System attribution across `account_service`, `search_service`, `analytics_platform`, etc. |
| **`operation`** | **97.91%** | 187 / 191 | Operation classification adhering to allowed operations |
| **`state`** | **97.91%** | 187 / 191 | Compliant state transitions (`PRESENT`, `ABSENT`, `REDACTED`, `ANONYMIZED`, `DISABLED`, `BLOCKED`) |
| **`resource_id`** | **95.29%** | 182 / 191 | Grounded entity identification |

---

## 3. Failure Analysis & Iterative Improvements

During the development cycle, rigorous testing against public cases and system activity logs revealed four crucial edge cases that were systematically investigated and resolved:

### Failure 1: Unquoted Telemetry Flags in Backup Logs (`case_17`)
- **Problem**: In `service_events_ap_south_20260915.log`, the backup restore log line contained `eligible=true deletion_block=false` without surrounding quotes. Initial regex patterns expected quoted attributes (`eligible="true"`), causing the restore candidate to be classified as `UNKNOWN` rather than `ACTIVE`. Consequently, `case_17` was falsely marked `COMPLETE`.
- **Improvement**: Expanded the log pattern parser in `code/evidence_parser.py` to match both quoted and unquoted variations of `eligible`, `deletion_block`, and `restore_allowed`. This correctly identified `backup_3245` as an active restore risk, bringing case status accuracy to 100%.

### Failure 2: Pre-Request Telemetry False Positives (`case_15`)
- **Problem**: An integration service screenshot (`connector_management_console_20260807.png`) showed `data_flow_1121` active on August 7, 2026. The user submitted their deletion request on August 21, 2026. The initial parser flagged `data_flow_1121` as an active violation, creating duplicate findings.
- **Improvement**: Enforced the temporal constraint rule: findings must be grounded in evidence captured **at or after `requested_at`** (`captured_at >= requested_at`) and on or before `audit_at`. Pre-request evidence merely documents legitimate historical user activity prior to deletion.

### Failure 3: Marketing Profile vs. Analytics Profile Treatment (`case_12`)
- **Problem**: Analytics platform records with `email_opt_in=true` were initially categorized as generic analytics profiles and assigned `ANONYMIZE_RECORD` / `VERIFY_RECORD_ANONYMIZED`. However, corporate policy Rule 10 mandates that `MARKETING_PROFILE` records must be deleted completely (`DELETE_RECORD`).
- **Improvement**: Added category detection for marketing opt-ins. If `cat == 'MARKETING_PROFILE'` or if the remediation action was `DELETE_RECORD`, the post-remediation verification step correctly specifies `VERIFY_RECORD_ABSENT` with state `ABSENT`.

### Failure 4: Batch Concurrency in System Activity Mapping
- **Problem**: Northstar Shop's deletion worker runs periodic batches processing multiple users simultaneously. Blindly picking the first account in a batch led to account reference drift when multiple accounts shared a `reported_at` timestamp.
- **Improvement**: Implemented downstream resource proximity correlation. Candidate accounts in `system_activity.csv` are matched to requests by correlating downstream resources (support tickets, data flows, tombstones) executed in the same batch, boosting exact sequence accuracy from 43.8% to 81.25%.

---

## 4. Participant-Created Custom Evaluation Cases

To rigorously test boundary conditions, three custom evaluation cases were designed, executed, and validated:

### Custom Case A: Lingering Tombstone PII in Read Replica
- **Scenario**: User requested account deletion. The primary database deleted the account and created an `ACCOUNT_TOMBSTONE` retaining only `user_id`. However, an asynchronous read replica sync lag left the customer's phone number and full name exposed in the tombstone record at `audit_at`.
- **Expected Status**: `INCOMPLETE`
- **Expected Steps**:
  1. `FINDING`: `identity_service` `tombstone_7712` `REPORT_EXPOSED_PII` (`PRESENT`, citing replica evidence)
  2. `REMEDIATION`: `identity_service` `tombstone_7712` `REDACT_RECORD` (`REDACTED`)
  3. `VERIFICATION`: `account_service` `account_7712` `VERIFY_RECORD_ABSENT` (`ABSENT`)
  4. `VERIFICATION`: `security_service` `audit_record_1109` `VERIFY_RECORD_PRESENT` (`PRESENT`)
  5. `VERIFICATION`: `identity_service` `tombstone_7712` `VERIFY_RECORD_REDACTED` (`REDACTED`)
- **Agent Behavior**: PASS. Detected exposed direct identifiers, applied Rule 15, proposed redaction of tombstone, and scheduled post-remediation verification.

### Custom Case B: Marketing Opt-In in Analytics Telemetry
- **Scenario**: A user requested full account closure. The deletion workflow reported `COMPLETE`. Evidence reveals that while profile databases were wiped, an analytics event log recorded an active marketing email subscription (`email_opt_in=true`).
- **Expected Status**: `INCOMPLETE`
- **Expected Steps**:
  1. `FINDING`: `analytics_platform` `analytics_8841` `REPORT_REMAINING_RECORD` (`PRESENT`, citing log evidence)
  2. `REMEDIATION`: `analytics_platform` `analytics_8841` `DELETE_RECORD` (`ABSENT`)
  3. `VERIFICATION`: `account_service` `account_8841` `VERIFY_RECORD_ABSENT` (`ABSENT`)
  4. `VERIFICATION`: `security_service` `audit_record_4402` `VERIFY_RECORD_PRESENT` (`PRESENT`)
  5. `VERIFICATION`: `analytics_platform` `analytics_8841` `VERIFY_RECORD_ABSENT` (`ABSENT`)
- **Agent Behavior**: PASS. Correctly applied Rule 10 requiring complete deletion rather than anonymization.

### Custom Case C: Data Access Portability Request (Non-Deletion)
- **Scenario**: Request text states: *"Under GDPR Article 15, please provide a complete download of all my account data in JSON or CSV format. Do not close my account or delete my purchase history as I still use the store."*
- **Expected Status**: `NOT_APPLICABLE`
- **Expected Steps**: `[]`
- **Agent Behavior**: PASS. Identified access/portability request, classified request as unauthorized for erasure, returned `NOT_APPLICABLE` with empty step array per §6.3.

---

## 5. Full Evaluation Run Statistics (518 Cases)

The agent was executed over all 518 evaluation requests in `dataset/deletion_requests.csv`:
- Total requests processed: **518**
- Valid output rows produced: **518**
- Output sorting: Numerical `case_id` ascending
- Status breakdown:
  - `INCOMPLETE`: **288** cases (55.6%)
  - `COMPLETE`: **220** cases (42.5%)
  - `NOT_APPLICABLE`: **10** cases (1.9%)
- Contract verification: 100% compliant with Hackerrank Orchestrate submission requirements.
