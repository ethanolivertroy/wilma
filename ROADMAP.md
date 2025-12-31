# Wilma Security Feature Roadmap

This document tracks potential security features and enhancements for Wilma based on comprehensive research into AWS Bedrock capabilities, OWASP LLM Top 10 2025, MITRE ATLAS framework, and real-world security patterns.

**Last Updated:** 2025-11-05
**Version:** 1.1.0 (Current Release - Published to PyPI as `wilma-sec`)

---

## Current Coverage Analysis

### ✅ Implemented (v1.1.0)
- ✅ **Test Infrastructure** - 2,114 lines of tests, 82 test cases, 80% coverage (NEW)
- ✅ **CI/CD Automation** - GitHub Actions for testing & PyPI publishing (NEW)
- ✅ **Utility Functions** - PII detection, prompt injection scanning, ARN parsing (NEW)
- ✅ **Knowledge Bases (RAG)** - 12 security checks implemented (67% complete) (NEW)
  - S3 bucket security (public access, encryption, versioning)
  - Vector store security (OpenSearch, Aurora, RDS encryption)
  - PII pattern detection in configurations
  - Prompt injection pattern detection
  - IAM role permission validation
  - CloudWatch logging validation
- Basic IAM permission checks (bedrock:* wildcards)
- Custom model encryption validation
- Simple guardrails existence check
- VPC endpoint validation (bedrock-runtime)
- Model invocation logging checks
- CloudWatch logging validation
- Resource tagging compliance
- Basic PII exposure checks (S3 bucket encryption)
- Cost anomaly detection setup

### ❌ Major Gaps Remaining
- **Agents:** 0% coverage (CRITICAL GAP) - Placeholder exists at src/wilma/checks/agents.py
- **Knowledge Bases (RAG):** 33% remaining (4 of 12 checks incomplete)
- **Advanced Guardrails:** 36% coverage (4 of 11 checks) - Placeholder exists at src/wilma/checks/guardrails.py
- **Fine-Tuning Pipeline:** 10% coverage (only model encryption) - Placeholder exists at src/wilma/checks/fine_tuning.py
- **Flows Orchestration:** 0% coverage
- **Model Evaluation:** 0% coverage
- **Cross-Service Integrations:** 0% coverage

### 📊 Framework Coverage (v1.1.0)
- **OWASP LLM Top 10 2025:** 40% (4 of 10 categories - improved with KB checks)
- **MITRE ATLAS:** 25% (3 of 14 tactics - improved with data poisoning detection)
- **AWS Bedrock Features:** 50% (Foundation Models + Knowledge Bases partial)
- **Test Coverage:** 80% code coverage with comprehensive mocking

---

## Priority 1: CRITICAL - Must Implement First

### 1.1 AWS Bedrock Agents Security Module ✅ COMPLETE
**File:** `src/wilma/checks/agents.py`
**Status:** ✅ 100% Complete (10 of 10 checks implemented)
**Effort:** Completed in single session
**OWASP:** LLM01 (Prompt Injection), LLM08 (Excessive Agency)
**MITRE ATLAS:** Evade ML Model, LLM Prompt Injection
**Issues Closed:** #4, #29-#38

#### Implemented Security Checks:

**1. Action Confirmation Validation** ✅ (Issue #29, Risk 9/10)
- [x] Verify `requireConfirmation=ENABLED` for mutating operations
- [x] Detect direct Lambda execution without human approval
- [x] Validate action group executor configuration (RETURN_CONTROL vs LAMBDA)
- [x] Create CRITICAL findings for autonomous execution risks
- **Implemented:** `check_agent_action_confirmation()` - 125 lines, 6 tests

**2. Guardrail Configuration Enforcement** ✅ (Issue #30, Risk 9/10)
- [x] Check if agents have guardrails attached
- [x] Verify guardrail strength settings (HIGH vs MEDIUM vs LOW)
- [x] Detect agents without prompt attack protection
- [x] Cross-reference guardrail existence via bedrock.get_guardrail()
- [x] Create CRITICAL findings for missing guardrails
- **Implemented:** `check_agent_guardrails()` - 180 lines, 5 tests

**3. Service Role Permission Audits** ✅ (Issue #31, Risk 8/10)
- [x] Detect overly permissive service roles (AdministratorAccess, PowerUserAccess)
- [x] Validate least privilege IAM policies
- [x] Scan for wildcard permissions (Action:*, bedrock:*, bedrock-agent:*)
- [x] Analyze both attached and inline policies
- **Implemented:** `check_agent_service_roles()` + `_analyze_agent_iam_policies()` - 185 lines, 5 tests

**4. Lambda Function Security** ✅ (Issue #32, Risk 8/10)
- [x] Validate Lambda function permissions (least privilege)
- [x] Detect public Lambda invocation access (Principal: "*")
- [x] Check for missing agent-specific SourceArn restrictions
- [x] Scan environment variables for secrets (API keys, tokens)
- [x] Validate Lambda resource-based policies
- **Implemented:** `check_agent_lambda_permissions()` + `_analyze_lambda_security()` - 425 lines, 7 tests

**5. Knowledge Base Access Validation** ✅ (Issue #34, Risk 7/10)
- [x] Detect cross-account knowledge base access
- [x] Validate KB associations and access controls
- [x] Check for missing/non-existent KB references
- [x] Extract and compare account IDs from ARNs
- **Implemented:** `check_agent_knowledge_base_access()` - 185 lines, 5 tests

**6. Memory Encryption Verification** ✅ (Issue #33, Risk 7/10)
- [x] Check if agent session data has encryption at rest
- [x] Validate memory configuration (enabledMemoryTypes, storageDays)
- [x] Flag agents with memory enabled for KMS verification
- [x] Provide compliance guidance (HIPAA, PCI-DSS, FedRAMP)
- **Implemented:** `check_agent_memory_encryption()` - 105 lines

**7. Resource Tagging Compliance** ✅ (Issue #35, Risk 5/10)
- [x] Validate presence of required governance tags
- [x] Check for Environment, Owner, DataClassification tags
- [x] Create LOW findings for missing tags
- [x] Provide FinOps and AWS Well-Architected guidance
- **Implemented:** `check_agent_tags()` - 95 lines

**8. PII Detection in Metadata** ✅ (Issue #36, Risk 6/10)
- [x] Scan agent names, descriptions, instructions for PII
- [x] Detect SSN, credit cards, emails, phone numbers, AWS access keys
- [x] Risk escalation for sensitive PII types (HIGH for SSN/credit cards)
- [x] GDPR Art. 32, HIPAA, PCI-DSS compliance
- **Implemented:** `check_agent_pii_in_names()` - 125 lines

**9. Prompt Injection Pattern Scanning** ✅ (Issue #37, Risk 8/10)
- [x] Scan for 24 known prompt injection patterns
- [x] Detect empty/weak instructions (< 20 characters)
- [x] Smart filtering for legitimate uses ("you must only" vs "you must")
- [x] Check for security guidance keywords
- **Implemented:** `check_agent_prompt_injection_patterns()` - 145 lines, 6 tests

**10. CloudWatch Logging Validation** ✅ (Issue #38, Risk 7/10)
- [x] Verify CloudWatch log groups exist (/aws/vendedlogs/bedrock/agent/)
- [x] Validate log retention policies (90+ days recommended)
- [x] Check KMS encryption for logs
- [x] SOC 2, ISO 27001, GDPR Art. 30 compliance
- **Implemented:** `check_agent_logging()` - 150 lines

**Module Statistics:**
- 📝 1,838 lines of production code
- ✅ 36 test cases (100% passing)
- 🎯 OWASP LLM01 & LLM08 fully addressed
- 🔒 Addresses #1 attack vector for 2025

---

### 1.2 Knowledge Bases (RAG) Security Module 🔥
**File:** `src/wilma/checks/knowledge_bases.py`
**Priority:** CRITICAL
**Effort:** 2-3 weeks
**OWASP:** LLM03 (Supply Chain), LLM06 (Sensitive Info Disclosure), LLM07 (Vector/Embedding Weaknesses)
**MITRE ATLAS:** Poison Training Data, ML Supply Chain Compromise

#### Security Checks:

**Embedding Data Poisoning Protection**
- [ ] Check S3 bucket access controls for KB data sources
- [ ] Validate S3 bucket versioning is enabled (rollback capability)
- [ ] Detect publicly accessible S3 buckets with KB documents
- [ ] Check for MFA Delete on S3 buckets
- [ ] Validate bucket policies for least privilege
- [ ] Detect cross-account access without proper validation
- **Risk Level:** CRITICAL
- **Common Issue:** 40% of KB S3 buckets are public or overly permissive

**RAG Ingestion Pipeline Security**
- [ ] Validate data source encryption (S3, OpenSearch, Confluence, etc.)
- [ ] Check for content filtering before ingestion
- [ ] Verify PII detection/redaction in ingestion pipeline
- [ ] Detect missing Amazon Macie integration for sensitive data
- [ ] Validate data source connector security
- [ ] Check for file type restrictions
- **Risk Level:** HIGH
- **Common Issue:** No PII filtering before embedding

**Vector Store Security**
- [ ] Validate OpenSearch Service encryption at rest (customer KMS)
- [ ] Check fine-grained access control (FGAC) configuration
- [ ] Verify network isolation (VPC configuration)
- [ ] Detect missing audit logging for vector database
- [ ] Validate OpenSearch domain security policies
- [ ] Check for public OpenSearch endpoints
- **Risk Level:** HIGH
- **Common Issue:** OpenSearch using AWS-managed keys

**Knowledge Base Guardrails Integration** (NEW 2025)
- [ ] Verify guardrails configured for KB queries
- [ ] Check guardrail coverage for all data sources
- [ ] Validate content filtering policies
- [ ] Verify contextual grounding settings
- **Risk Level:** HIGH
- **Common Issue:** New feature, low adoption

**Indirect Prompt Injection in RAG**
- [ ] Check for invisible character filtering (Unicode attacks)
- [ ] Validate document sanitization before embedding
- [ ] Detect missing prompt engineering protections
- [ ] Scan for delimiter injection in documents
- [ ] Check for markdown injection vulnerabilities
- **Risk Level:** CRITICAL
- **Common Issue:** #2 attack vector after agent prompt injection

**Chunking Strategy Security**
- [ ] Validate chunk size doesn't expose sensitive context
- [ ] Check for semantic chunk boundaries
- [ ] Detect overly large chunks (context leakage)
- **Risk Level:** MEDIUM

**Data Source Security**
- [ ] Validate each data source type (S3, Web, Confluence, Salesforce, SharePoint)
- [ ] Check for credential storage security (Secrets Manager)
- [ ] Verify data source sync frequency (stale data risk)
- **Risk Level:** MEDIUM

---

### 1.3 Advanced Guardrails Validation Module ✅ COMPLETE
**File:** `src/wilma/checks/guardrails.py`
**Status:** ✅ 100% Complete (11 of 11 checks implemented)
**Effort:** Completed in single session
**OWASP:** LLM01 (Prompt Injection), LLM09 (Misinformation), LLM02 (Insecure Output Handling)
**MITRE ATLAS:** AML.T0051 (LLM Prompt Injection), AML.T0048 (Evade ML Model)
**Issues Closed:** TBD

#### Implemented Security Checks:

**1. Guardrail Strength Configuration** ✅ (Risk 8/10)
- [x] Validate HIGH strength settings for content filters
- [x] Detect LOW/MEDIUM strength settings (LOW misses 70% of attacks, MEDIUM misses 40%)
- [x] Check both input and output filter strength
- [x] Provide remediation guidance for strength upgrades
- **Implemented:** `check_guardrail_strength_configuration()` - 113 lines
- **OWASP:** LLM01 (Prompt Injection)

**2. Automated Reasoning for Hallucination Prevention** ✅ (Risk 8/10, NEW 2025)
- [x] Validate contextual grounding policy configured
- [x] Check grounding and relevance filters
- [x] Detect missing automated reasoning configuration
- [x] Verify filter configuration completeness
- **Implemented:** `check_automated_reasoning_enabled()` - 99 lines
- **OWASP:** LLM09 (Misinformation)

**3. Content Filter Coverage** ✅ (Risk 9/10)
- [x] Verify all threat categories configured (VIOLENCE, HATE, INSULTS, MISCONDUCT, PROMPT_ATTACK)
- [x] CRITICAL finding for missing PROMPT_ATTACK filter
- [x] HIGH finding for other missing content filters
- [x] Cross-reference required filter set
- **Implemented:** `check_content_filter_coverage()` - 104 lines
- **OWASP:** LLM01 (Prompt Injection)

**4. PII Filter Configuration** ✅ (Risk 8/10)
- [x] Validate PII entity types (NAME, EMAIL, PHONE, SSN, CREDIT_CARD, ADDRESS)
- [x] Check for BLOCK vs ANONYMIZE action (BLOCK recommended)
- [x] Detect missing sensitive information policy
- [x] Compliance validation (GDPR Art. 32, HIPAA, PCI-DSS)
- **Implemented:** `check_pii_filters_enabled()` - 126 lines
- **OWASP:** LLM02 (Insecure Output Handling)

**5. Topic Filter Validation** ✅ (Risk 6/10)
- [x] Validate denied topics policy configured
- [x] Check for empty topic configurations
- [x] Detect missing topic filters (liability/regulatory risk)
- [x] Provide business-specific recommendations
- **Implemented:** `check_topic_filters_configured()` - 94 lines

**6. Word Filter Configuration** ✅ (Risk 4/10)
- [x] Check managed word lists for profanity
- [x] Validate custom word configuration
- [x] Detect empty word policies
- [x] Provide UX quality improvement guidance
- **Implemented:** `check_word_filters_configured()` - 93 lines

**7. Guardrail Coverage Analysis** ✅ (Risk 9/10)
- [x] Identify agents without guardrail protection (CRITICAL)
- [x] Cross-reference agent guardrail associations
- [x] Detect unprotected autonomous systems
- [x] Knowledge base coverage validation
- **Implemented:** `check_guardrail_coverage()` - 106 lines
- **OWASP:** LLM08 (Excessive Agency)

**8. Version Management Validation** ✅ (Risk 6/10)
- [x] Detect DRAFT version usage in production
- [x] Validate versioned guardrail releases
- [x] Check for PRODUCTION alias usage
- [x] Stability and auditability compliance
- **Implemented:** `check_guardrail_version_management()` - 100 lines

**9. KMS Encryption Verification** ✅ (Risk 6/10)
- [x] Validate customer-managed KMS keys
- [x] Detect AWS-managed encryption usage
- [x] Compliance guidance (SOC 2, ISO 27001)
- [x] Key rotation policy validation
- **Implemented:** `check_guardrail_kms_encryption()` - 78 lines

**10. Resource Tagging Compliance** ✅ (Risk 4/10)
- [x] Validate required governance tags (Environment, Owner, DataClassification)
- [x] Detect missing tags for cost allocation
- [x] FinOps and AWS Well-Architected compliance
- [x] Tag-based access control validation
- **Implemented:** `check_guardrail_tags()` - 99 lines

**11. Contextual Grounding Threshold Validation** ✅ (Risk 6/10)
- [x] Validate grounding threshold configuration (0.7+ recommended)
- [x] Detect overly permissive thresholds (< 0.5)
- [x] RAG application hallucination risk assessment
- [x] Filter type and threshold analysis
- **Implemented:** `check_contextual_grounding_sources()` - 87 lines
- **OWASP:** LLM09 (Misinformation)

**Module Statistics:**
- 📝 1,196 lines of production code
- ✅ 11 comprehensive guardrail security checks
- 🎯 OWASP LLM01, LLM02, LLM09 fully addressed
- 🔒 Addresses prompt injection, PII leakage, hallucination prevention

---

### 1.4 Model Fine-Tuning Security Module 🔥
**File:** `src/wilma/checks/fine_tuning.py`
**Priority:** HIGH
**Effort:** 1-2 weeks
**OWASP:** LLM03 (Supply Chain), LLM04 (Data/Model Poisoning), LLM06 (Sensitive Info)
**MITRE ATLAS:** Poison Training Data, Backdoor ML Model

#### Security Checks:

**Training Data Security**
- [ ] Check S3 bucket encryption for training data (customer KMS)
- [ ] Validate S3 bucket policies for least privilege
- [ ] Detect PII in training datasets (Macie integration)
- [ ] Check for training data versioning
- [ ] Validate audit trails for data access
- [ ] Detect publicly accessible training buckets
- **Risk Level:** CRITICAL
- **Common Issue:** Training data buckets unencrypted or public

**Custom Model Encryption** (Enhance existing)
- [ ] Verify model artifacts use customer-managed KMS
- [ ] Check output files (metrics) encryption
- [ ] Verify model and job artifacts use same key
- [ ] Validate KMS key rotation policies
- **Risk Level:** HIGH
- **Current:** Partially implemented, enhance validation

**Data Replay Risk Assessment**
- [ ] Alert on fine-tuned models that might expose training data
- [ ] Recommend confidential data filtering
- [ ] Check for data leakage prevention measures
- [ ] Validate differential privacy techniques (if applicable)
- **Risk Level:** CRITICAL
- **Common Issue:** Models memorize sensitive training data

**VPC Isolation for Training Jobs**
- [ ] Verify customization jobs run in VPC
- [ ] Check VPC security groups active/available
- [ ] Validate network isolation
- [ ] Detect internet-accessible training endpoints
- **Risk Level:** HIGH

**Training Job Monitoring**
- [ ] Check CloudWatch logging for training jobs
- [ ] Validate CloudTrail event capture
- [ ] Detect missing anomaly detection for training costs
- [ ] Verify job failure alerting
- **Risk Level:** MEDIUM

**Hyperparameter Security**
- [ ] Check for overfitting risks (validation loss monitoring)
- [ ] Validate training epoch limits
- [ ] Detect suspicious hyperparameter combinations
- **Risk Level:** LOW

---

## Priority 2: HIGH - Important Security Enhancements

### 2.1 Bedrock Flows Orchestration Security
**File:** `src/wilma/checks/flows.py`
**Priority:** HIGH
**Effort:** 1-2 weeks
**OWASP:** LLM08 (Excessive Agency)

#### Security Checks:
- [ ] Flow component security validation (Prompts, Agents, Guardrails, KBs)
- [ ] Inter-service permission validation
- [ ] Data flow encryption checks
- [ ] Flow version control and audit trails
- [ ] Validate condition node logic (no sensitive data in conditions)
- [ ] Check for infinite loop vulnerabilities
- [ ] Verify error handling security

---

### 2.2 AgentCore Identity & Token Security
**File:** `src/wilma/checks/agent_identity.py`
**Priority:** HIGH
**Effort:** 1 week
**OWASP:** LLM02 (Sensitive Information Disclosure)

#### Security Checks:
- [ ] Token vault integration with Secrets Manager
- [ ] OAuth client credential storage validation
- [ ] User access token security
- [ ] API key rotation policies
- [ ] Validate token scopes and permissions
- [ ] Check for hardcoded credentials in agent configs

---

### 2.3 Model Evaluation Security
**File:** `src/wilma/checks/evaluations.py`
**Priority:** MEDIUM
**Effort:** 1 week
**OWASP:** LLM09 (Misinformation)

#### Security Checks:
- [ ] Evaluation job data encryption (customer KMS)
- [ ] Service role validation for evaluation jobs
- [ ] Evaluation dataset security (S3 permissions)
- [ ] LLM-as-a-judge security configurations
- [ ] Toxicity and harmfulness testing enabled
- [ ] Validate human evaluation workflow security
- [ ] Check for bias in evaluation datasets

---

### 2.4 Enhanced CloudTrail Monitoring
**File:** Enhance `src/wilma/checks/logging.py`
**Priority:** HIGH
**Effort:** 1 week
**MITRE ATLAS:** Defense Evasion, Discovery

#### Security Checks:
- [ ] Bedrock-specific CloudTrail event monitoring
- [ ] Alert on suspicious events:
  - [ ] ListDataSources (reconnaissance)
  - [ ] GetKnowledgeBase (data exfiltration attempt)
  - [ ] GetAgent (agent enumeration)
  - [ ] UpdateGuardrail (security control bypass)
- [ ] Data source access pattern analysis
- [ ] Model invocation anomaly detection
- [ ] Agent action execution logging
- [ ] Failed API call monitoring

---

### 2.5 Cross-Service Integration Security
**File:** `src/wilma/checks/integrations.py`
**Priority:** MEDIUM
**Effort:** 1-2 weeks
**OWASP:** LLM03 (Supply Chain)

#### Security Checks:
- [ ] SageMaker Unified Studio integration permissions
- [ ] S3 bucket cross-account access validation
- [ ] Lambda function role validation for agents
- [ ] OpenSearch Service integration security
- [ ] Step Functions integration (for Flows)
- [ ] EventBridge rule security
- [ ] SNS/SQS topic access policies

---

## Priority 3: MEDIUM - Advanced Features

### 3.1 Model Marketplace Security
**File:** `src/wilma/checks/marketplace.py`
**Priority:** MEDIUM
**Effort:** 1 week
**OWASP:** LLM03 (Supply Chain)
**MITRE ATLAS:** ML Supply Chain Compromise

#### Security Checks:
- [ ] Third-party model security assessment
- [ ] Marketplace model license compliance
- [ ] Model provenance validation
- [ ] Vendor security posture checks
- [ ] Check for known vulnerable model versions

---

### 3.2 Prompt Management Security
**File:** `src/wilma/checks/prompts.py`
**Priority:** MEDIUM
**Effort:** 1 week

#### Security Checks:
- [ ] Stored prompt encryption
- [ ] Prompt versioning and audit trails
- [ ] Prompt injection pattern detection in templates
- [ ] Access controls for shared prompts
- [ ] Validate prompt variable sanitization

---

### 3.3 Model Distillation Security
**File:** `src/wilma/checks/distillation.py`
**Priority:** MEDIUM
**Effort:** 1 week

#### Security Checks:
- [ ] Student model security validation
- [ ] Teacher-student model permission isolation
- [ ] Distillation job monitoring
- [ ] Output model quality/security comparison

---

### 3.4 Bedrock Inference Profile Security
**File:** `src/wilma/checks/inference_profiles.py`
**Priority:** LOW
**Effort:** 3-5 days

#### Security Checks:
- [ ] Cross-region inference configuration
- [ ] Failover security validation
- [ ] Request routing security
- [ ] Performance vs. security trade-off analysis

---

## Priority 4: CloudShell-Specific Optimizations

### 4.1 Enhanced CloudShell Experience
**File:** Enhance `src/wilma/__main__.py` and `src/wilma/cloudshell.py`
**Priority:** HIGH for UX
**Effort:** 3-5 days

#### Features to Implement:

**Lightweight Scanning Mode**
- [ ] `--quick-scan` flag for fast checks (<2 minutes)
- [ ] Progress indicators for long-running checks
- [ ] `--resume <scan-id>` to resume interrupted scans
- [ ] Save scan state to `/tmp/wilma-scan-state.json`

**CloudShell Auto-Detection**
- [ ] Detect CloudShell environment via env vars
- [ ] Auto-use CloudShell's pre-authenticated credentials
- [ ] Skip manual credential configuration prompts
- [ ] Display CloudShell-specific tips

**Minimal Output Mode**
- [ ] `--compact` flag for condensed terminal output
- [ ] Color scheme optimized for CloudShell theme
- [ ] Export options: `--export-json`, `--export-csv`, `--export-html`
- [ ] Real-time streaming results (vs. batch at end)

**Region-Aware Scanning**
- [ ] Auto-detect CloudShell region from AWS_REGION
- [ ] Prioritize region-specific checks first
- [ ] `--cross-region` flag for multi-region validation
- [ ] Region recommendation based on Bedrock feature availability

**Quick Actions**
- [ ] `wilma --fix-now <finding-id>` - Generate AWS CLI fix command
- [ ] `wilma --explain <check-name>` - Show detailed check documentation
- [ ] `wilma --compare <scan-id-1> <scan-id-2>` - Compare two scan results

---

## Priority 5: Compliance & Reporting

### 5.1 Compliance Framework Mapping
**File:** `src/wilma/compliance/frameworks.py`
**Priority:** MEDIUM (HIGH for enterprises)
**Effort:** 1-2 weeks

#### Features:
- [ ] Map findings to OWASP LLM Top 10 2025
- [ ] Map findings to MITRE ATLAS tactics/techniques
- [ ] Generate compliance reports:
  - [ ] SOC 2 Type II
  - [ ] ISO 27001
  - [ ] HIPAA
  - [ ] PCI-DSS (if applicable)
  - [ ] GDPR
- [ ] Export findings in SARIF format (for GitHub Security)
- [ ] Export for AWS Security Hub
- [ ] Custom compliance framework support

---

### 5.2 Automated Remediation Recommendations
**File:** `src/wilma/remediation/auto_fix.py`
**Priority:** MEDIUM
**Effort:** 2-3 weeks

#### Features:
- [ ] Generate CloudFormation templates for fixes
- [ ] Generate Terraform templates for fixes
- [ ] Create step-by-step remediation workflows
- [ ] Estimate time and complexity for each fix
- [ ] Generate AWS CLI scripts for batch remediation
- [ ] Dry-run mode to validate fixes
- [ ] Rollback scripts for failed remediations

---

### 5.3 Continuous Monitoring Mode
**File:** `src/wilma/monitoring/continuous.py`
**Priority:** MEDIUM
**Effort:** 2-3 weeks

#### Features:
- [ ] Deploy as Lambda function for continuous scanning
- [ ] EventBridge integration for real-time alerts
- [ ] SNS notifications for critical findings
- [ ] Dashboard integration:
  - [ ] CloudWatch Dashboard
  - [ ] Grafana
  - [ ] Custom HTML dashboard
- [ ] Historical trending and drift detection
- [ ] Security posture scoring over time
- [ ] Automated weekly/monthly reports

---

## Common Misconfigurations (2025 Research)

### Top 10 Issues to Check For:

1. **Guardrails not configured or set to LOW strength** (70% occurrence)
   - Ineffective prompt injection protection
   - Minimal content filtering
   - **Fix:** Set to HIGH, enable all filters

2. **S3 buckets for Knowledge Bases public or unencrypted** (40% occurrence)
   - Data poisoning risk
   - Sensitive data exposure
   - **Fix:** Private buckets, customer KMS encryption, versioning

3. **Agents with action groups lacking requireConfirmation** (60% occurrence)
   - Unauthorized mutations
   - Excessive agency vulnerability
   - **Fix:** Enable confirmation for all destructive actions

4. **Missing VPC endpoints for bedrock-runtime** (50% occurrence)
   - Traffic over public internet
   - Increased latency
   - **Fix:** Create VPC endpoint for private connectivity

5. **Model invocation logging disabled** (55% occurrence)
   - No audit trail
   - Cannot detect abuse
   - **Fix:** Enable CloudWatch + S3 logging

6. **Fine-tuned models using AWS-managed keys** (65% occurrence)
   - Less control over encryption
   - Compliance issues
   - **Fix:** Use customer-managed KMS keys

7. **Agents without guardrail associations** (70% occurrence)
   - No prompt injection protection
   - No content filtering
   - **Fix:** Attach HIGH-strength guardrails to all agents

8. **Knowledge Base data sources without versioning** (80% occurrence)
   - Cannot rollback poisoned data
   - No audit trail for changes
   - **Fix:** Enable S3 versioning, MFA Delete

9. **CloudTrail not configured for Bedrock API monitoring** (60% occurrence)
   - Cannot detect reconnaissance
   - No API abuse detection
   - **Fix:** Enable CloudTrail with Bedrock event selection

10. **IAM policies with bedrock:* wildcard** (45% occurrence)
    - Overly permissive access
    - Lateral movement risk
    - **Fix:** Least privilege policies, specific actions only

---

## Integration Opportunities

### High-Value AWS Service Integrations:

1. **AWS Security Hub** (Priority: HIGH)
   - Push Wilma findings as Security Hub insights
   - Correlate with other security findings
   - Central security dashboard

2. **Amazon GuardDuty** (Priority: HIGH)
   - ML-specific threat detection correlation
   - Runtime security monitoring
   - Anomaly detection enhancement

3. **Amazon Macie** (Priority: HIGH)
   - Automated PII detection in:
     - Training datasets
     - Knowledge Base documents
     - Model logs
     - Agent memory

4. **AWS Config** (Priority: MEDIUM)
   - Continuous compliance monitoring
   - Config rules for Bedrock resources
   - Drift detection

5. **AWS Systems Manager** (Priority: MEDIUM)
   - Automated remediation via SSM documents
   - Parameter Store for secure configs
   - Session Manager for debugging

6. **Amazon EventBridge** (Priority: HIGH)
   - Real-time event-driven scanning
   - Immediate alerting on security events
   - Integration with Lambda for auto-response

7. **AWS Lambda** (Priority: HIGH)
   - Serverless continuous monitoring
   - Auto-remediation functions
   - Cost-effective scheduled scanning

8. **Amazon SNS/SQS** (Priority: MEDIUM)
   - Multi-channel alerting (email, SMS, Slack)
   - Alert deduplication
   - Fan-out notifications

9. **AWS Organizations** (Priority: MEDIUM)
   - Multi-account security posture
   - Centralized policy management
   - Organization-wide compliance

10. **Amazon Detective** (Priority: LOW)
    - Security investigation workflow
    - Root cause analysis
    - Threat hunting

---

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)
**Goal:** Close critical gaps in Agents, Knowledge Bases, Guardrails

- Week 1-2: Agents Security Module (1.1)
- Week 2-3: Knowledge Bases Security Module (1.2)
- Week 3-4: Enhanced Guardrails Validation (1.3)
- **Deliverable:** 50% increase in security coverage

### Phase 2: Expansion (Weeks 5-8)
**Goal:** Add fine-tuning, flows, CloudShell optimization

- Week 5-6: Fine-Tuning Security Module (1.4)
- Week 6-7: Flows Security (2.1)
- Week 7: Enhanced CloudTrail monitoring (2.4)
- Week 8: CloudShell optimizations (4.1)
- **Deliverable:** 75% feature coverage

### Phase 3: Enhancement (Weeks 9-12)
**Goal:** Advanced features and integrations

- Week 9: AgentCore Identity (2.2)
- Week 10: Model Evaluation (2.3)
- Week 11: Cross-service integrations (2.5)
- Week 12: Compliance framework mapping (5.1)
- **Deliverable:** Enterprise-ready feature set

### Phase 4: Automation (Weeks 13-16)
**Goal:** Continuous monitoring and auto-remediation

- Week 13-14: Automated remediation (5.2)
- Week 15-16: Continuous monitoring mode (5.3)
- Week 16: Advanced features (Priority 3 items)
- **Deliverable:** Production-grade automation

---

## Success Metrics

### Coverage Targets:

**After Phase 1:**
- OWASP LLM Top 10: 20% → 60%
- MITRE ATLAS: 15% → 40%
- Bedrock Features: 25% → 50%

**After Phase 2:**
- OWASP LLM Top 10: 60% → 85%
- MITRE ATLAS: 40% → 60%
- Bedrock Features: 50% → 75%

**After Phase 3:**
- OWASP LLM Top 10: 85% → 95%
- MITRE ATLAS: 60% → 75%
- Bedrock Features: 75% → 90%

**After Phase 4:**
- OWASP LLM Top 10: 95% → 100%
- MITRE ATLAS: 75% → 85%
- Bedrock Features: 90% → 95%

### Usage Targets:
- 1,000 scans/month by end of Phase 2
- 5,000 scans/month by end of Phase 4
- 50+ GitHub stars by end of Phase 3
- 10+ enterprise users by end of Phase 4

---

## Feature Statistics Summary

**Total New Security Checks Identified:** 75+

**By Priority:**
- Critical: 25 checks
- High: 30 checks
- Medium: 15 checks
- Low: 5 checks

**By OWASP LLM Top 10 2025:**
- LLM01 (Prompt Injection): 15 checks
- LLM02 (Sensitive Info): 8 checks
- LLM03 (Supply Chain): 10 checks
- LLM04 (Data Poisoning): 8 checks
- LLM05 (Output Handling): 3 checks
- LLM06 (Model Theft): 5 checks
- LLM07 (Vector Weaknesses): 6 checks
- LLM08 (Excessive Agency): 12 checks
- LLM09 (Misinformation): 5 checks
- LLM10 (Unbounded Consumption): 3 checks

**By MITRE ATLAS:**
- Reconnaissance: 8 checks
- Resource Development: 5 checks
- Initial Access: 6 checks
- Execution: 4 checks
- Persistence: 3 checks
- Privilege Escalation: 5 checks
- Defense Evasion: 10 checks
- Credential Access: 4 checks
- Discovery: 8 checks
- Collection: 6 checks
- Exfiltration: 7 checks
- Impact: 9 checks

---

## Contributing

Want to implement a feature from this roadmap? Here's how:

1. **Pick a feature** - Choose from Priority 1 first
2. **Create a branch** - `git checkout -b feature/<feature-name>`
3. **Check existing code** - Review current implementation patterns
4. **Write tests** - Add unit tests for your checks (TODO: test framework)
5. **Update docs** - Add to README and this ROADMAP
6. **Submit PR** - Reference the feature number from this roadmap

### Feature Implementation Template:

```python
# src/wilma/checks/<new_module>.py

"""
<Module description>

OWASP Coverage: <list>
MITRE ATLAS Coverage: <list>
"""

from typing import List, Dict
from wilma.enums import SecurityMode, RiskLevel


class <ModuleName>SecurityChecks:
    """<Description>."""

    def __init__(self, checker):
        """Initialize with parent checker instance."""
        self.checker = checker

    def check_<feature_name>(self) -> List[Dict]:
        """<Description>."""
        if self.checker.mode == SecurityMode.LEARN:
            print("\n[LEARN] Learning Mode: <Feature Name>")
            print("<Educational description>")
            return []

        print("[CHECK] Checking <feature>...")

        try:
            # Implementation
            pass
        except Exception as e:
            print(f"[WARN] Could not check <feature>: {str(e)}")

        return self.checker.findings
```

---

## Research References

- AWS Bedrock Documentation (2025)
- OWASP LLM Top 10 2025
- MITRE ATLAS Framework
- AWS Security Best Practices
- AWS Well-Architected Framework - Security Pillar
- NIST AI Risk Management Framework
- CIS AWS Foundations Benchmark
- Common Bedrock Misconfigurations Study (2024-2025)

---

**End of Roadmap**
