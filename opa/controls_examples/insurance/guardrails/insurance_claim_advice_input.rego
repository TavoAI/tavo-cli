package tavoai.insurance.guardrails.insurance_claim_advice_input

# Runtime guardrail for insurance claim advice input validation
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230
# Specific to insurance industry

# Import common modules
import data.tavoai.common.input_validation
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow insurance claim advice input if all checks pass
allow if {
    # Basic validation checks
    input_validation.allow
    
    # Verify this is an input document
    input.content_type == "input"
    
    # Insurance-specific input checks
    insurance_claim_advice_input_checks
}

# Core insurance claim advice input checks
insurance_claim_advice_input_checks if {
    # Check if the input request is appropriate for insurance claim advice
    not contains_prohibited_insurance_requests(input.content)
    
    # Check if configuration is appropriate for insurance content
    insurance_config_check
}

# Helper function to detect prohibited insurance requests
contains_prohibited_insurance_requests(text) if {
    prohibited_patterns := [
        "(?i)guarantee.{1,30}claim.{1,30}approval",
        "(?i)commit.{1,30}(payout|settlement)",
        "(?i)promise.{1,30}(coverage|payment)",
        "(?i)bypass.{1,30}(process|investigation|assessment)",
        "(?i)avoid.{1,30}(detection|investigation|review)",
        "(?i)fake.{1,30}claim"
    ]
    
    pattern := prohibited_patterns[_]
    regex.match(pattern, text)
}

# Check if configuration is appropriate for insurance content
insurance_config_check if {
    # For insurance content, misinformation detection should be enabled
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

# Insurance input specific rejection reasons
document_type_reasons = reasons if {
    not input.content_type == "input"
    reasons := [{"category": "Content Type", "reason": "Expected input document but received another type"}]
} else = [] if {
    true
}

prohibited_request_reasons = reasons if {
    contains_prohibited_insurance_requests(input.content)
    reasons := [{"category": "Insurance Request", "reason": "Input contains requests for prohibited insurance claim activities"}]
} else = [] if {
    true
}

config_reasons = reasons if {
    not insurance_config_check
    reasons := [{"category": "Configuration", "reason": "Misinformation detection must be enabled for insurance claim queries"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Insurance Claim Advice Input Guardrail",
    "description": "Input validation guardrail for insurance claim advice in GenAI applications",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "APRA CPS 230",
        "ASIC RG 271",
        "State Insurance Regulatory Guidelines"
    ]
} 