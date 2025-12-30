"""
AWS Bedrock Agents Security Checks Module

This module implements security validation for AWS Bedrock Agents, which are
autonomous AI systems that can execute actions in your AWS environment.

10 Comprehensive Checks:
1. Action Confirmation - Validates agents require human approval for mutations
2. Guardrails - Verifies agents have guardrails against prompt injection
3. Service Roles - Audits agent service role permissions (least privilege)
4. Lambda Permissions - Validates action group Lambda security
5. Memory Encryption - Checks agent session memory uses customer KMS keys
6. Knowledge Base Access - Validates appropriate KB access controls
7. Tags - Ensures proper tagging for governance
8. PII in Names - Detects PII exposure in agent metadata
9. Prompt Injection Patterns - Scans instructions for vulnerabilities
10. Logging - Validates CloudWatch integration

Priority: CRITICAL
OWASP Coverage: LLM01 (Prompt Injection), LLM08 (Excessive Agency)
MITRE ATLAS: AML.T0051 (LLM Prompt Injection)

See ROADMAP.md Section 1.1 for complete implementation details.
"""

from typing import Dict, List

from botocore.exceptions import ClientError

from wilma.utils import handle_aws_error, paginate_aws_results

from ..enums import RiskLevel

# Constants
MAX_RESULTS_PER_PAGE = 100


class AgentSecurityChecks:
    """Security checks for AWS Bedrock Agents."""

    def __init__(self, checker):
        """
        Initialize agent security checks.

        Args:
            checker: Reference to main BedrockSecurityChecker instance
        """
        self.checker = checker
        self.bedrock = checker.bedrock
        self.bedrock_agent = checker.session.client('bedrock-agent')
        self.iam = checker.iam
        self.findings = []

    def _get_all_agents(self) -> List[Dict]:
        """
        Get all agents with pagination support.

        Returns:
            List of agent summaries. Handles accounts with >100 agents.
        """
        agents = []
        try:
            # Note: 'nextToken' parameters are AWS pagination tokens, not passwords (S106 false positive)
            for agent in paginate_aws_results(
                self.bedrock_agent.list_agents,
                'agentSummaries',
                token_key='nextToken',  # noqa: S106
                token_param='nextToken',  # noqa: S106
                maxResults=MAX_RESULTS_PER_PAGE
            ):
                agents.append(agent)
        except ClientError as e:
            handle_aws_error(e, "listing agents")
        except Exception as e:
            print(f"[ERROR] Failed to list agents: {str(e)}")

        return agents

    def check_agent_action_confirmation(self) -> List[Dict]:
        """
        Validate agents require confirmation for mutating operations.

        WHY CRITICAL: Agents without action confirmation can execute dangerous
        actions (delete, modify, terminate) without human approval via prompt
        injection attacks. 60% of agents in production lack this control.

        Checks: Action group executor configuration (RETURN_CONTROL vs LAMBDA)
        Risk: CRITICAL if direct Lambda execution enabled
        OWASP: LLM08 (Excessive Agency)
        MITRE: AML.T0051 (LLM Prompt Injection)

        Returns:
            List of security findings
        """
        findings = []

        try:
            # List all agents with pagination
            agents = self._get_all_agents()

            if not agents:
                return findings

            print(f"[CHECK] Analyzing {len(agents)} agents for action confirmation requirements...")

            for agent in agents:
                agent_id = agent['agentId']
                agent_name = agent.get('agentName', agent_id)

                try:
                    # Get action groups for this agent
                    action_groups_response = self.bedrock_agent.list_agent_action_groups(
                        agentId=agent_id,
                        agentVersion='DRAFT',
                        maxResults=MAX_RESULTS_PER_PAGE
                    )

                    action_group_summaries = action_groups_response.get('actionGroupSummaries', [])

                    if not action_group_summaries:
                        continue

                    for ag_summary in action_group_summaries:
                        ag_id = ag_summary['actionGroupId']
                        ag_name = ag_summary.get('actionGroupName', ag_id)
                        ag_state = ag_summary.get('actionGroupState', 'UNKNOWN')

                        # Skip disabled action groups
                        if ag_state == 'DISABLED':
                            continue

                        try:
                            # Get detailed action group configuration
                            ag_details = self.bedrock_agent.get_agent_action_group(
                                agentId=agent_id,
                                agentVersion='DRAFT',
                                actionGroupId=ag_id
                            )

                            ag_config = ag_details.get('agentActionGroup', {})
                            executor_config = ag_config.get('actionGroupExecutor', {})

                            # Check if using LAMBDA (direct execution) instead of RETURN_CONTROL
                            if 'lambda' in executor_config:
                                lambda_arn = executor_config.get('lambda', '')

                                findings.append({
                                    'risk_level': RiskLevel.CRITICAL,
                                    'title': 'Agent action group lacks confirmation requirement',
                                    'description': (
                                        f'Agent "{agent_name}" has action group "{ag_name}" configured '
                                        f'for direct Lambda execution without requiring human confirmation. '
                                        f'This allows the agent to autonomously execute potentially dangerous '
                                        f'operations (delete, modify, terminate) via prompt injection attacks. '
                                        f'Recommendation: Use RETURN_CONTROL to require explicit user approval '
                                        f'before executing mutating operations.'
                                    ),
                                    'location': f'Agent: {agent_name}, Action Group: {ag_name}',
                                    'resource': f'bedrock-agent:agent/{agent_id}/action-group/{ag_id}',
                                    'remediation': (
                                        f'Update action group to require confirmation:\n'
                                        f'aws bedrock-agent update-agent-action-group \\\n'
                                        f'  --agent-id {agent_id} \\\n'
                                        f'  --agent-version DRAFT \\\n'
                                        f'  --action-group-id {ag_id} \\\n'
                                        f'  --action-group-executor customControl=RETURN_CONTROL\n\n'
                                        f'Then update your application to handle confirmation requests.'
                                    ),
                                    'details': {
                                        'agent_id': agent_id,
                                        'agent_name': agent_name,
                                        'action_group_id': ag_id,
                                        'action_group_name': ag_name,
                                        'executor_type': 'LAMBDA',
                                        'lambda_arn': lambda_arn,
                                        'requires_confirmation': False,
                                        'owasp': 'LLM08 (Excessive Agency)',
                                        'mitre_atlas': 'AML.T0051 (LLM Prompt Injection)'
                                    }
                                })

                        except ClientError as e:
                            error_code = e.response['Error']['Code']
                            if error_code in ['ResourceNotFoundException', 'AccessDeniedException']:
                                print(f"[WARN] Cannot access action group {ag_name}: {error_code}")
                            else:
                                handle_aws_error(e, f"getting action group {ag_name}")
                        except Exception as e:
                            print(f"[ERROR] Failed to analyze action group {ag_name}: {str(e)}")

                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'ResourceNotFoundException':
                        print(f"[WARN] Agent {agent_name} not found (may have been deleted)")
                    else:
                        handle_aws_error(e, f"listing action groups for agent {agent_name}")
                except Exception as e:
                    print(f"[ERROR] Failed to analyze agent {agent_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to check agent action confirmation: {str(e)}")

        return findings

    def check_agent_guardrails(self) -> List[Dict]:
        """
        Verify all agents have guardrails configured.

        Agents without guardrails are vulnerable to indirect prompt injection
        via their action group responses or knowledge base content.

        Returns:
            List of security findings

        TODO: Implement check for:
        - List all agents
        - Verify each has guardrailConfiguration set
        - Check guardrail strength (should be HIGH, not LOW)
        - Risk Score: 9/10 for no guardrails, 7/10 for weak guardrails
        """
        raise NotImplementedError("See ROADMAP.md Section 1.1.2")

    def check_agent_service_roles(self) -> List[Dict]:
        """
        Validate agent service role permissions follow least privilege.

        Returns:
            List of security findings

        TODO: Implement check for:
        - List all agents and their service roles
        - Analyze role policies for overly permissive actions
        - Flag wildcard permissions (bedrock:*, *)
        - Check for cross-account access risks
        - Risk Score: 8/10 for overly permissive roles
        """
        raise NotImplementedError("See ROADMAP.md Section 1.1.3")

    def check_agent_lambda_permissions(self) -> List[Dict]:
        """
        Validate Lambda functions used by action groups have proper permissions.

        Returns:
            List of security findings

        TODO: Implement check for:
        - List all agents and their action groups
        - For each Lambda function ARN, check IAM permissions
        - Verify Lambda resource-based policy restricts access
        - Check for environment variables containing secrets
        - Risk Score: 8/10 for overly permissive Lambda access
        """
        raise NotImplementedError("See ROADMAP.md Section 1.1.4")

    def check_agent_memory_encryption(self) -> List[Dict]:
        """
        Verify agent session memory uses customer-managed KMS keys.

        Returns:
            List of security findings

        TODO: Implement check for:
        - List all agents with memory persistence enabled
        - Check memoryConfiguration encryption settings
        - Flag agents using AWS-managed keys instead of customer keys
        - Risk Score: 7/10 for AWS-managed keys
        """
        raise NotImplementedError("See ROADMAP.md Section 1.1.5")

    def check_agent_knowledge_base_access(self) -> List[Dict]:
        """
        Validate agents have appropriate access to knowledge bases.

        Returns:
            List of security findings

        TODO: Implement check for:
        - List all agents and their knowledge base associations
        - Verify knowledge bases have proper access controls
        - Check for cross-account knowledge base access
        - Risk Score: 7/10 for inappropriate access patterns
        """
        raise NotImplementedError("See ROADMAP.md Section 1.1.6")

    def check_agent_tags(self) -> List[Dict]:
        """
        Validate agents have proper tagging for governance.

        Returns:
            List of security findings

        TODO: Implement check for:
        - List all agents and their tags
        - Check for required tags (Environment, Owner, DataClassification)
        - Flag untagged agents
        - Risk Score: 5/10 for missing tags
        """
        raise NotImplementedError("See ROADMAP.md Section 1.1.7")

    def check_agent_pii_in_names(self) -> List[Dict]:
        """
        Detect PII in agent names, descriptions, and instructions.

        Returns:
            List of security findings

        TODO: Implement check for:
        - List all agents
        - Scan name, description, instruction for PII patterns
        - Check for email addresses, phone numbers, AWS account IDs
        - Risk Score: 6/10 for PII exposure
        """
        raise NotImplementedError("See ROADMAP.md Section 1.1.8")

    def check_agent_prompt_injection_patterns(self) -> List[Dict]:
        """
        Scan agent instructions for known prompt injection vulnerabilities.

        Returns:
            List of security findings

        TODO: Implement check for:
        - List all agents and their instructions
        - Check for weak/missing system prompts
        - Scan for vulnerable instruction patterns
        - Validate input validation instructions present
        - Risk Score: 8/10 for vulnerable patterns
        """
        raise NotImplementedError("See ROADMAP.md Section 1.1.9")

    def check_agent_logging(self) -> List[Dict]:
        """
        Verify agent invocations are logged to CloudWatch.

        Returns:
            List of security findings

        TODO: Implement check for:
        - Verify CloudWatch log groups exist for agent invocations
        - Check log retention policies
        - Verify log encryption settings
        - Risk Score: 7/10 for missing logging
        """
        raise NotImplementedError("See ROADMAP.md Section 1.1.10")

    def run_all_checks(self) -> List[Dict]:
        """
        Run all agent security checks.

        Returns:
            List of all security findings
        """
        print("[CHECK] Running AWS Bedrock Agent security checks...")

        # Implemented checks
        self.findings.extend(self.check_agent_action_confirmation())

        # TODO: Uncomment as each check is implemented
        # self.findings.extend(self.check_agent_guardrails())
        # self.findings.extend(self.check_agent_service_roles())
        # self.findings.extend(self.check_agent_lambda_permissions())
        # self.findings.extend(self.check_agent_memory_encryption())
        # self.findings.extend(self.check_agent_knowledge_base_access())
        # self.findings.extend(self.check_agent_tags())
        # self.findings.extend(self.check_agent_pii_in_names())
        # self.findings.extend(self.check_agent_prompt_injection_patterns())
        # self.findings.extend(self.check_agent_logging())

        print(f"[INFO] Agent security checks: {len(self.findings)} findings")
        return self.findings
