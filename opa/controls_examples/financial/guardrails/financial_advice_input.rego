package tavoai.financial.guardrails.financial_advice_input

# Runtime guardrail for financial advice input validation
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230
# Specific to financial industry

# Import common guardrails and pattern definitions
import data.tavoai.common.input_validation
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow financial advice input if all checks pass
allow if {
    # Input validation
    input_validation.allow
    
    # Additional input-specific checks
    input.content_type == "input"  # Verify this is an input document
    financial_input_checks
}

# Additional checks specific to financial advice inputs
financial_input_checks if {
    # Check if the input is appropriate for financial advice
    not contains_prohibited_financial_requests(input.content)
}

# Helper function to detect prohibited financial requests
contains_prohibited_financial_requests(text) if {
    prohibited_patterns := [
        "(?i)guaranteed (returns|profits|income)",
        "(?i)risk-free investment",
        "(?i)get rich quick",
        "(?i)avoid (taxes|taxation)",
        "(?i)tax (evasion|avoidance)",
        "(?i)inside (information|trading)",
        "(?i)pump and dump",
        "(?i)market manipulation"
    ]
    
    pattern := prohibited_patterns[_]
    regex.match(pattern, text)
}

# Rejection reasons
rejection_reasons = reasons if {
    reasons := array.concat(
        input_validation_rejection_reasons,
        financial_input_rejection_reasons
    )
}

# Input validation rejection reasons
input_validation_rejection_reasons = reasons if {
    not input_validation.allow
    reasons := input_validation.rejection_reasons
} else = [] if {
    true
}

# Financial input specific rejection reasons
financial_input_rejection_reasons = reasons if {
    not input.content_type == "input"
    reasons := [{"category": "Content Type", "reason": "Expected input document but received another type"}]
} else = reasons if {
    contains_prohibited_financial_requests(input.content)
    reasons := [{"category": "Financial Input", "reason": "Input contains requests for prohibited financial advice"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Financial Advice Input Guardrail",
    "description": "Input validation guardrail for financial advice in GenAI applications",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "APRA CPS 230"
    ]
} 