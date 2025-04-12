package tavoai.common.input_validation

# Runtime guardrail for input validation in GenAI and Agentic AI applications
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230

# Import centralized pattern definitions
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow input if all checks pass
allow if {
    # Verify this is an input document
    input.content_type == "input"
    
    # Length checks
    input_length_compliant
    
    # Content checks
    prohibited_content_compliant
    
    # PII checks
    pii_compliant
    
    # Security checks
    security_compliant
    
    # Rate limiting
    rate_limit_compliant
}

# Input length compliance
input_length_compliant if {
    # Skip length check if configurations are not provided
    not input.config.max_input_length
    not input.config.min_input_length
}

input_length_compliant if {
    # Skip max length check if max_input_length is not provided
    not input.config.max_input_length
    # But still check min length if it's provided
    input.config.min_input_length
    count(input.content) >= input.config.min_input_length
}

input_length_compliant if {
    # Skip min length check if min_input_length is not provided
    not input.config.min_input_length
    # But still check max length if it's provided
    input.config.max_input_length
    count(input.content) <= input.config.max_input_length
}

input_length_compliant if {
    # Both length configs are provided, check both
    input.config.max_input_length
    input.config.min_input_length
    count(input.content) <= input.config.max_input_length
    count(input.content) >= input.config.min_input_length
}

# Prohibited content compliance
prohibited_content_compliant if {
    # If no prohibited categories are defined, always compliant
    not patterns.prohibited_categories
}

prohibited_content_compliant if {
    # Check each category
    prohibited_categories := patterns.prohibited_categories
    category := prohibited_categories[_]
    
    # Get patterns for this category
    patterns_for_category := patterns.prohibited_content_patterns[category]
    
    # For each pattern in the category
    pattern := patterns_for_category[_]
    
    # Ensure input doesn't match the pattern
    not regex.match(pattern, input.content)
}

# PII compliance
pii_compliant if {
    # If PII detection is disabled, always compliant
    not input.config.pii_detection_enabled
}

pii_compliant if {
    # PII detection is enabled and PII is not allowed
    input.config.pii_detection_enabled
    
    # Ensure NO PII is detected - fails if any pattern matches
    not contains_pii(input.content)
}

# Helper rule to detect if content contains any PII pattern
contains_pii(text) if {
    pii_patterns := patterns.pii_patterns
    pattern_key := object.keys(pii_patterns)[_]
    pattern := pii_patterns[pattern_key]
    regex.match(pattern, text)
}

# Security compliance
security_compliant if {
    # If no security patterns are defined, always compliant
    not patterns.injection_patterns
    not patterns.jailbreak_patterns
}

security_compliant if {
    # Check for prompt injection attempts
    not prompt_injection_detected
    
    # Check for jailbreak attempts
    not jailbreak_attempt_detected
}

# Prompt injection detection using centralized patterns
prompt_injection_detected if {
    pattern := patterns.injection_patterns[_]
    regex.match(pattern, input.content)
}

# Jailbreak attempt detection using centralized patterns
jailbreak_attempt_detected if {
    pattern := patterns.jailbreak_patterns[_]
    regex.match(pattern, input.content)
}

# Rate limit compliance
rate_limit_compliant if {
    # If rate limiting is disabled, always compliant
    not input.config.rate_limiting_enabled
}

rate_limit_compliant if {
    # Rate limiting is enabled
    input.config.rate_limiting_enabled
    
    # Check user's request count against limits
    input.user_request_count <= input.config.rate_limit
    input.time_since_last_request >= input.config.min_request_interval
}

# Get reasons for input rejection
rejection_reasons = reasons if {
    # Fixed array.concat to properly nest the calls with only 2 arguments per call
    reasons := array.concat(
        document_type_reasons,
        array.concat(
            length_reasons,
            array.concat(
                prohibited_content_reasons,
                array.concat(
                    pii_reasons,
                    array.concat(
                        security_reasons,
                        rate_limit_reasons
                    )
                )
            )
        )
    )
}

document_type_reasons = reasons if {
    not input.content_type == "input"
    reasons := [{"category": "Content Type", "reason": "Expected input document but received another type"}]
} else = [] if {
    true
}

length_reasons = reasons if {
    not input_length_compliant
    count(input.content) > input.config.max_input_length
    reasons := [{"category": "Length", "reason": sprintf("Input exceeds maximum length of %d characters", [input.config.max_input_length])}]
} else = reasons if {
    not input_length_compliant
    count(input.content) < input.config.min_input_length
    reasons := [{"category": "Length", "reason": sprintf("Input is shorter than minimum length of %d characters", [input.config.min_input_length])}]
} else = [] if {
    true
}

prohibited_content_reasons = reasons if {
    prohibited_categories := patterns.prohibited_categories
    category := prohibited_categories[_]
    patterns_for_category := patterns.prohibited_content_patterns[category]
    pattern := patterns_for_category[_]
    regex.match(pattern, input.content)
    reasons := [{"category": "Prohibited Content", "reason": sprintf("Input contains prohibited content from category: %s", [category])}]
} else = [] if {
    true
}

pii_reasons = reasons if {
    input.config.pii_detection_enabled
    not input.config.pii_allowed_with_consent
    pii_patterns := patterns.pii_patterns
    pattern_key := object.keys(pii_patterns)[_]
    pattern := pii_patterns[pattern_key]
    regex.match(pattern, input.content)
    reasons := [{"category": "PII", "reason": sprintf("Input contains personal identifiable information (%s)", [pattern_key])}]
} else = reasons if {
    input.config.pii_detection_enabled
    input.config.pii_allowed_with_consent
    not input.pii_consent_obtained
    pii_patterns := patterns.pii_patterns
    pattern_key := object.keys(pii_patterns)[_]
    pattern := pii_patterns[pattern_key]
    regex.match(pattern, input.content)
    reasons := [{"category": "PII", "reason": sprintf("Input contains PII (%s) but consent has not been obtained", [pattern_key])}]
} else = [] if {
    true
}

security_reasons = array.concat(injection_reasons, jailbreak_reasons)

injection_reasons = reasons if {
    pattern := patterns.injection_patterns[_]
    regex.match(pattern, input.content)
    reasons := [{"category": "Security", "reason": "Input contains potential prompt injection attempt"}]
} else = [] if {
    true
}

jailbreak_reasons = reasons if {
    pattern := patterns.jailbreak_patterns[_]
    regex.match(pattern, input.content)
    reasons := [{"category": "Security", "reason": "Input contains potential jailbreak attempt"}]
} else = [] if {
    true
}

rate_limit_reasons = reasons if {
    input.config.rate_limiting_enabled
    input.user_request_count > input.config.rate_limit
    reasons := [{"category": "Rate Limiting", "reason": sprintf("Rate limit of %d requests exceeded", [input.config.rate_limit])}]
} else = reasons if {
    input.config.rate_limiting_enabled
    input.time_since_last_request < input.config.min_request_interval
    reasons := [{"category": "Rate Limiting", "reason": sprintf("Request interval too short, minimum is %d seconds", [input.config.min_request_interval])}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Input Validation Guardrail",
    "description": "Runtime guardrail for validating and sanitizing inputs to GenAI systems",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "APRA CPS 230"
    ]
} 