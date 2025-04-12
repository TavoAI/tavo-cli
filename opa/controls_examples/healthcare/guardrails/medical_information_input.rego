package tavoai.healthcare.guardrails.medical_information_input

# Runtime guardrail for medical information input validation
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230
# Specific to healthcare industry

# Import common modules
import data.tavoai.common.input_validation
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow medical information input if all checks pass
allow if {
    # Basic validation checks
    input_validation.allow
    
    # Verify this is an input document
    input.content_type == "input"
    
    # Healthcare-specific input checks
    medical_input_checks
}

# Core medical information input checks
medical_input_checks if {
    # Check if the input request is appropriate for medical information
    not contains_prohibited_medical_requests(input.content)
    
    # Check if configuration is appropriate for medical content
    medical_config_check
}

# Helper function to detect prohibited medical requests
contains_prohibited_medical_requests(text) if {
    prohibited_patterns := [
        "(?i)prescribe.{1,20}medication",
        "(?i)diagnose.{1,20}condition",
        "(?i)write.{1,20}prescription",
        "(?i)medical license",
        "(?i)certify.{1,20}health",
        "(?i)treat.{1,20}(disease|condition)",
        "(?i)sign.{1,20}medical"
    ]
    
    pattern := prohibited_patterns[_]
    regex.match(pattern, text)
}

# Check if configuration is appropriate for medical content
medical_config_check if {
    # For medical content, misinformation detection should be enabled
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

# Medical input specific rejection reasons
document_type_reasons = reasons if {
    not input.content_type == "input"
    reasons := [{"category": "Content Type", "reason": "Expected input document but received another type"}]
} else = [] if {
    true
}

prohibited_request_reasons = reasons if {
    contains_prohibited_medical_requests(input.content)
    reasons := [{"category": "Medical Request", "reason": "Input contains requests for prohibited medical services such as diagnosis or prescription"}]
} else = [] if {
    true
}

config_reasons = reasons if {
    not medical_config_check
    reasons := [{"category": "Configuration", "reason": "Misinformation detection must be enabled for medical information queries"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Medical Information Input Guardrail",
    "description": "Input validation guardrail for medical information in GenAI applications",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "APRA CPS 230",
        "FDA Regulations",
        "HIPAA"
    ]
} 