# Priority 1 GitHub Issues Tracking

This document tracks the Priority 1 security features to be implemented in Wilma. Use these as templates for creating GitHub issues.

---

## Issue #1: Implement AWS Bedrock Agents Security Module

**Labels:** `priority-critical`, `security-feature`, `agents`, `owasp-llm01`, `owasp-llm08`

### Title
[PRIORITY 1] Implement AWS Bedrock Agents Security Module

### Description
Implement comprehensive security validation for AWS Bedrock Agents, which can execute actions in AWS environments and represent a significant attack vector if misconfigured.

**Current Gap:** Wilma has zero checks for Bedrock Agents, leaving a critical blind spot in GenAI security posture.

### Security Impact
- **OWASP Coverage:** LLM01 (Prompt Injection), LLM08 (Excessive Agency)
- **MITRE ATLAS:** AML.T0051 (LLM Prompt Injection)
- **Risk Level:** CRITICAL (9-10)

### Implementation Details
**File:** `src/wilma/checks/agents.py` (placeholder already created)

**Security Checks to Implement:**
1. Agent action confirmation (requireConfirmation=ENABLED) - Risk: 9/10
2. Guardrail configuration validation - Risk: 9/10
3. Service role permission audit (least privilege) - Risk: 8/10
4. Lambda function permission validation - Risk: 8/10
5. Memory persistence encryption (customer KMS) - Risk: 7/10
6. Knowledge base access validation - Risk: 7/10
7. Tagging compliance check - Risk: 5/10
8. PII detection in agent names/descriptions - Risk: 6/10
9. Prompt injection pattern scanning - Risk: 8/10
10. CloudWatch logging validation - Risk: 7/10

### Acceptance Criteria
- [ ] All 10 security checks implemented and tested
- [ ] Integration with main BedrockSecurityChecker
- [ ] Beginner mode provides clear explanations
- [ ] Expert mode includes technical details
- [ ] Risk scores calibrated appropriately
- [ ] Remediation commands provided for each finding
- [ ] Documentation updated in README.md
- [ ] Unit tests added (when test framework established)

### Estimated Effort
2-3 weeks

### Prerequisites
- AWS Bedrock Agent API access
- bedrock-agent client configuration
- Sample test environments with agents

### Related Documentation
- [AWS Bedrock Agents Documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html)
- ROADMAP.md Section 1.1

---

## Issue #2: Implement AWS Bedrock Knowledge Bases Security Module

**Labels:** `priority-critical`, `security-feature`, `knowledge-bases`, `rag`, `owasp-llm03`, `owasp-llm06`

### Title
[PRIORITY 1] Implement AWS Bedrock Knowledge Bases (RAG) Security Module

### Description
Implement security validation for AWS Bedrock Knowledge Bases, which handle proprietary data and enable RAG implementations. Compromised knowledge bases can lead to data poisoning and information disclosure.

**Current Gap:** No validation of RAG implementations, S3 bucket security, or vector store configurations.

### Security Impact
- **OWASP Coverage:** LLM03 (Training Data Poisoning), LLM06 (Sensitive Info Disclosure)
- **MITRE ATLAS:** AML.T0020 (Poison Training Data)
- **Risk Level:** CRITICAL (9-10)

### Implementation Details
**File:** `src/wilma/checks/knowledge_bases.py` (placeholder already created)

**Security Checks to Implement:**
1. S3 bucket public access validation - Risk: 10/10
2. S3 bucket encryption verification - Risk: 8/10
3. Vector store encryption (OpenSearch/Aurora) - Risk: 8/10
4. Vector store access control validation - Risk: 9/10
5. PII detection in embeddings (Macie integration) - Risk: 9/10
6. Indirect prompt injection in documents - Risk: 8/10
7. S3 versioning enabled check - Risk: 7/10
8. Knowledge base access pattern analysis - Risk: 7/10
9. Chunking configuration validation - Risk: 6/10
10. CloudWatch logging validation - Risk: 7/10
11. Tagging compliance check - Risk: 5/10
12. Embedding model access control - Risk: 6/10

### Acceptance Criteria
- [ ] All 12 security checks implemented and tested
- [ ] Amazon Macie integration for PII detection
- [ ] Support for OpenSearch, Aurora, Pinecone, and Redis vector stores
- [ ] Integration with main BedrockSecurityChecker
- [ ] Beginner and expert mode support
- [ ] Remediation guidance for each finding
- [ ] Documentation updated
- [ ] Unit tests added (when framework established)

### Estimated Effort
2-3 weeks

### Prerequisites
- AWS Bedrock Agent API access (knowledge bases)
- Amazon Macie client configuration
- S3, OpenSearch, and Aurora client access
- Sample test environments with knowledge bases

### Related Documentation
- [AWS Bedrock Knowledge Bases Documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base.html)
- ROADMAP.md Section 1.2

---

## Issue #3: Implement Advanced Guardrails Validation Module

**Labels:** `priority-critical`, `security-feature`, `guardrails`, `owasp-llm01`, `owasp-llm02`

### Title
[PRIORITY 1] Implement Advanced Guardrails Validation Module

### Description
Enhance guardrail checks beyond simple existence validation to verify configuration strength and effectiveness. Current implementation only checks IF guardrails exist, not HOW they're configured.

**Current Gap:** Weak guardrails with LOW strength or missing filters provide false sense of security.

### Security Impact
- **OWASP Coverage:** LLM01 (Prompt Injection), LLM02 (Insecure Output Handling)
- **MITRE ATLAS:** AML.T0051 (LLM Prompt Injection)
- **Risk Level:** CRITICAL (8-9)

### Implementation Details
**File:** `src/wilma/checks/guardrails.py` (placeholder already created)

**Security Checks to Implement:**
1. Guardrail strength configuration (HIGH vs LOW/MEDIUM) - Risk: 8/10
2. Automated Reasoning enabled check (NEW 2025 feature) - Risk: 7/10
3. Content filter coverage for all threat categories - Risk: 9/10
4. PII filters enabled and configured - Risk: 8/10
5. Topic filters configured - Risk: 6/10
6. Word filters (managed/custom) configured - Risk: 5/10
7. Guardrail coverage analysis (which resources lack them) - Risk: 9/10
8. Version management validation (DRAFT vs production) - Risk: 7/10
9. KMS encryption validation - Risk: 6/10
10. Tagging compliance check - Risk: 4/10
11. Contextual grounding sources for RAG - Risk: 7/10

### Acceptance Criteria
- [ ] All 11 security checks implemented and tested
- [ ] Support for 2025 Automated Reasoning features
- [ ] Coverage analysis across agents, models, and applications
- [ ] Integration with main BedrockSecurityChecker
- [ ] Beginner and expert mode support
- [ ] Remediation guidance for strengthening guardrails
- [ ] Documentation updated
- [ ] Unit tests added (when framework established)

### Estimated Effort
1-2 weeks

### Prerequisites
- AWS Bedrock Guardrails API access
- CloudTrail integration for usage pattern analysis
- Sample test environments with various guardrail configurations

### Related Documentation
- [AWS Bedrock Guardrails Documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)
- [Automated Reasoning for Bedrock](https://aws.amazon.com/bedrock/guardrails/)
- ROADMAP.md Section 1.3

---

## Issue #4: Implement Model Fine-Tuning Security Module

**Labels:** `priority-high`, `security-feature`, `fine-tuning`, `owasp-llm03`, `owasp-llm06`

### Title
[PRIORITY 1] Implement Model Fine-Tuning Security Module

### Description
Implement security validation for the model fine-tuning pipeline, focusing on training data security and preventing data leakage from fine-tuned models.

**Current Gap:** Only basic custom model encryption checks exist. Training pipeline security is not validated.

### Security Impact
- **OWASP Coverage:** LLM03 (Training Data Poisoning), LLM06 (Sensitive Info Disclosure)
- **MITRE ATLAS:** AML.T0020 (Poison Training Data), AML.T0024 (Backdoor ML Model)
- **Risk Level:** HIGH (7-9)

### Implementation Details
**File:** `src/wilma/checks/fine_tuning.py` (placeholder already created)

**Security Checks to Implement:**
1. Training data S3 bucket security audit - Risk: 10/10 for public, 8/10 for weak encryption
2. Training data PII detection (Macie integration) - Risk: 9/10
3. Model data replay risk assessment - Risk: 8/10
4. VPC isolation for training jobs - Risk: 7/10
5. Training job logging validation - Risk: 7/10
6. Output model encryption (customer KMS) - Risk: 7/10
7. S3 access logging for training data - Risk: 6/10
8. Training job IAM roles audit - Risk: 8/10
9. Custom model tagging compliance - Risk: 5/10
10. Training data source validation - Risk: 9/10
11. Model card documentation check - Risk: 4/10

### Acceptance Criteria
- [ ] All 11 security checks implemented and tested
- [ ] Amazon Macie integration for PII detection
- [ ] Data replay risk scoring algorithm
- [ ] Integration with main BedrockSecurityChecker
- [ ] Beginner and expert mode support
- [ ] Remediation guidance for each finding
- [ ] Documentation updated
- [ ] Unit tests added (when framework established)

### Estimated Effort
2 weeks

### Prerequisites
- AWS Bedrock Model Customization API access
- Amazon Macie client configuration
- S3 client access for bucket analysis
- Sample fine-tuning jobs for testing

### Related Documentation
- [AWS Bedrock Model Customization](https://docs.aws.amazon.com/bedrock/latest/userguide/custom-models.html)
- ROADMAP.md Section 1.4

---

## Creating These Issues

To create these issues on GitHub:

### Option 1: Manual Creation
1. Go to https://github.com/ethanolivertroy/wilma/issues/new
2. Copy the content from each issue above
3. Add the appropriate labels
4. Submit the issue

### Option 2: Using GitHub CLI
```bash
# Install gh CLI if needed: brew install gh

# Authenticate
gh auth login

# Create Issue #1 - Agents
gh issue create \
  --title "[PRIORITY 1] Implement AWS Bedrock Agents Security Module" \
  --label "priority-critical,security-feature,agents,owasp-llm01,owasp-llm08" \
  --body-file issue1-agents.md

# Create Issue #2 - Knowledge Bases
gh issue create \
  --title "[PRIORITY 1] Implement AWS Bedrock Knowledge Bases (RAG) Security Module" \
  --label "priority-critical,security-feature,knowledge-bases,rag,owasp-llm03,owasp-llm06" \
  --body-file issue2-kb.md

# Create Issue #3 - Guardrails
gh issue create \
  --title "[PRIORITY 1] Implement Advanced Guardrails Validation Module" \
  --label "priority-critical,security-feature,guardrails,owasp-llm01,owasp-llm02" \
  --body-file issue3-guardrails.md

# Create Issue #4 - Fine-Tuning
gh issue create \
  --title "[PRIORITY 1] Implement Model Fine-Tuning Security Module" \
  --label "priority-high,security-feature,fine-tuning,owasp-llm03,owasp-llm06" \
  --body-file issue4-finetuning.md
```

### Recommended Labels to Create
Before creating issues, add these labels to your repository:
- `priority-critical` (red)
- `priority-high` (orange)
- `security-feature` (purple)
- `agents` (blue)
- `knowledge-bases` (blue)
- `guardrails` (blue)
- `fine-tuning` (blue)
- `owasp-llm01` through `owasp-llm10` (yellow)
- `mitre-atlas` (yellow)

---

## Implementation Order

Based on risk and impact:

1. **Week 1-3:** Issue #2 (Knowledge Bases) - Highest risk (public S3 = 10/10)
2. **Week 4-6:** Issue #1 (Agents) - High risk + most common attack vector
3. **Week 7-8:** Issue #3 (Guardrails) - Foundation for all other protections
4. **Week 9-10:** Issue #4 (Fine-Tuning) - Important but less immediate risk

Total estimated time: 10 weeks for Priority 1 features.
