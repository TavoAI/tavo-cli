package tavoai.superannuation.guardrails.retirement_advice_input

# Runtime guardrail for retirement advice input validation
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230
# Specific to retirement and superannuation industry

# Import common modules
import data.tavoai.common.input_validation
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow retirement advice input if all checks pass
allow if {
    # Basic validation checks
    input_validation.allow
    
    # Verify this is an input document
    input.content_type == "input"
    
    # Superannuation-specific input checks
    retirement_advice_input_checks
}

# Core retirement advice input checks
retirement_advice_input_checks if {
    # Check if the input request is appropriate for retirement advice
    not contains_prohibited_retirement_requests(input.content)
    
    # Check if configuration is appropriate for retirement advice
    retirement_config_check
}

# Helper function to detect prohibited retirement advice requests
contains_prohibited_retirement_requests(text) if {
    prohibited_patterns := [
        "(?i)guarantee.{1,30}return",
        "(?i)promise.{1,30}(growth|performance)",
        "(?i)certain.{1,30}(gain|profit)",
        "(?i)risk-free.{1,30}investment",
        "(?i)sure.{1,30}bet",
        "(?i)can't lose"
    ]
    
    pattern := prohibited_patterns[_]
    regex.match(pattern, text)
}

# Check if configuration is appropriate for retirement advice
retirement_config_check if {
    # For retirement advice, misinformation detection should be enabled
    input.config.misinformation_detection_enabled == true
}

# Rejection reasons
rejection_reasons = reasons if {
    reasons := array.concat(
        input_validation_rejection_reasons,
        array.concat(
            document_type_reasons,
            array.concat(
                prohibited_request_reasons,
                config_reasons
            )
        )
    )
}

# Input validation rejection reasons
input_validation_rejection_reasons = reasons if {
    not input_validation.allow
    reasons := input_validation.rejection_reasons
} else = [] if {
    true
}

# Retirement advice input specific rejection reasons
document_type_reasons = reasons if {
    not input.content_type == "input"
    reasons := [{"category": "Content Type", "reason": "Expected input document but received another type"}]
} else = [] if {
    true
}

prohibited_request_reasons = reasons if {
    contains_prohibited_retirement_requests(input.content)
    reasons := [{"category": "Retirement Request", "reason": "Input contains requests for prohibited retirement advice such as guaranteed returns"}]
} else = [] if {
    true
}

config_reasons = reasons if {
    not retirement_config_check
    reasons := [{"category": "Configuration", "reason": "Misinformation detection must be enabled for retirement advice queries"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Retirement Advice Input Guardrail",
    "description": "Input validation guardrail for retirement advice in GenAI applications",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "APRA CPS 230",
        "ASIC RG 255",
        "ERISA",
        "DOL Fiduciary Rule"
    ]
} 