package tavoai.common.output_filtering

# Runtime guardrail for output filtering in GenAI and Agentic AI applications
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230

# Import centralized pattern definitions
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow output if all checks pass
allow if {
    # Verify this is an output document
    input.content_type == "output"
    
    # Prohibited content check
    prohibited_content_compliant
    
    # PII disclosure check
    pii_disclosure_compliant
    
    # Harmful content check
    harmful_content_compliant
    
    # Misinformation check
    misinformation_compliant
    
    # Bias check
    bias_compliant
}

# Prohibited content compliance
prohibited_content_compliant if {
    # Use centralized prohibited categories
    prohibited_categories := patterns.prohibited_categories
    
    # Check each category
    category := prohibited_categories[_]
    
    # Get patterns for this category
    patterns_for_category := patterns.prohibited_content_patterns[category]
    
    # For each pattern in the category
    pattern := patterns_for_category[_]
    
    # Ensure output doesn't match the pattern
    not regex.match(pattern, input.content)
}

# PII disclosure compliance
pii_disclosure_compliant if {
    # If PII detection is disabled, always compliant
    not input.config.pii_detection_enabled
} else if {
    # PII detection is enabled
    input.config.pii_detection_enabled
    
    # If PII is allowed with consent, check consent
    input.config.pii_allowed_with_consent
    input.pii_consent_obtained
} else if {
    # PII detection is enabled and PII is not allowed to be disclosed
    input.config.pii_detection_enabled
    not input.config.pii_allowed_with_consent
    
    # Check that no PII is detected in output using centralized patterns
    pii_patterns := patterns.pii_patterns
    pattern_key := object.keys(pii_patterns)[_]
    pattern := pii_patterns[pattern_key]
    not regex.match(pattern, input.content)
}

# Harmful content compliance
harmful_content_compliant if {
    # Use centralized harmful categories
    harmful_categories := patterns.harmful_categories
    
    # Check each category
    category := harmful_categories[_]
    
    # Get patterns for category
    harmful_patterns := patterns.harmful_content_patterns[category]
    
    # For each pattern in the category
    pattern := harmful_patterns[_]
    
    # Ensure output doesn't match the pattern
    not regex.match(pattern, input.content)
}

# Misinformation compliance
misinformation_compliant if {
    # If misinformation detection is disabled, always compliant
    not input.config.misinformation_detection_enabled
} else if {
    # Check factual claims against verified facts
    factual_claims := extract_factual_claims(input.content)
    claim := factual_claims[_]
    
    # Verify claim against knowledge base
    verify_claim(claim, input.config.knowledge_base)
}

# Bias compliance
bias_compliant if {
    # If bias detection is disabled, always compliant
    not input.config.bias_detection_enabled
} else if {
    # Analyze content for potential bias using centralized patterns
    # Note: In a more comprehensive implementation, you would define bias patterns
    # in the centralized patterns file
    not bias_detected(input.content, input.config.bias_patterns)
}

# Helper function to detect bias
bias_detected(text, bias_patterns) if {
    pattern := bias_patterns[_]
    regex.match(pattern, text)
}

# Extract factual claims (simplified example)
extract_factual_claims(text) = claims if {
    # This is a simplified version; in reality you would use NLP
    # or other methods to extract factual claims
    claims := ["simplifiedClaim"]
}

# Verify claim against knowledge base (simplified example)
verify_claim(claim, kb) if {
    # In a real implementation, this would check claims against a knowledge base
    # For simplicity, we'll assume all claims are valid
    true
}

# Rejection reasons
rejection_reasons = reasons if {
    # Fixed array.concat to properly nest the calls with only 2 arguments per call
    reasons := array.concat(
        document_type_reasons,
        array.concat(
            prohibited_content_reasons,
            array.concat(
                pii_disclosure_reasons,
                array.concat(
                    harmful_content_reasons,
                    array.concat(
                        misinformation_reasons,
                        bias_reasons
                    )
                )
            )
        )
    )
}

document_type_reasons = reasons if {
    not input.content_type == "output"
    reasons := [{"category": "Content Type", "reason": "Expected output document but received another type"}]
} else = [] if {
    true
}

prohibited_content_reasons = reasons if {
    prohibited_categories := patterns.prohibited_categories
    category := prohibited_categories[_]
    patterns_for_category := patterns.prohibited_content_patterns[category]
    pattern := patterns_for_category[_]
    regex.match(pattern, input.content)
    reasons := [{"category": "Prohibited Content", "reason": sprintf("Output contains prohibited content from category: %s", [category])}]
} else = [] if {
    true
}

pii_disclosure_reasons = reasons if {
    input.config.pii_detection_enabled
    not input.config.pii_allowed_with_consent
    pii_patterns := patterns.pii_patterns
    pattern_key := object.keys(pii_patterns)[_]
    pattern := pii_patterns[pattern_key]
    regex.match(pattern, input.content)
    reasons := [{"category": "PII Disclosure", "reason": sprintf("Output contains personal identifiable information (%s) that shouldn't be disclosed", [pattern_key])}]
} else = reasons if {
    input.config.pii_detection_enabled
    input.config.pii_allowed_with_consent
    not input.pii_consent_obtained
    pii_patterns := patterns.pii_patterns
    pattern_key := object.keys(pii_patterns)[_]
    pattern := pii_patterns[pattern_key]
    regex.match(pattern, input.content)
    reasons := [{"category": "PII Disclosure", "reason": sprintf("Output contains PII (%s) but consent for disclosure has not been obtained", [pattern_key])}]
} else = [] if {
    true
}

harmful_content_reasons = reasons if {
    harmful_categories := patterns.harmful_categories
    category := harmful_categories[_]
    harmful_patterns := patterns.harmful_content_patterns[category]
    pattern := harmful_patterns[_]
    regex.match(pattern, input.content)
    reasons := [{"category": "Harmful Content", "reason": sprintf("Output contains potentially harmful content from category: %s", [category])}]
} else = [] if {
    true
}

misinformation_reasons = reasons if {
    input.config.misinformation_detection_enabled
    factual_claims := extract_factual_claims(input.content)
    claim := factual_claims[_]
    not verify_claim(claim, input.config.knowledge_base)
    reasons := [{"category": "Misinformation", "reason": "Output contains potential misinformation or unverified claims"}]
} else = [] if {
    true
}

bias_reasons = reasons if {
    input.config.bias_detection_enabled
    bias_detected(input.content, input.config.bias_patterns)
    reasons := [{"category": "Bias", "reason": "Output contains potentially biased content"}]
} else = [] if {
    true
}

# Redaction and sanitization
sanitize_output(output) = sanitized_output if {
    # Apply PII redaction if needed
    redacted_pii := redact_pii(output, patterns.pii_patterns)
    
    # Apply harmful content redaction
    redacted_harmful := redact_harmful_content(redacted_pii, patterns.harmful_content_patterns)
    
    # Apply bias mitigation
    sanitized_output := mitigate_bias(redacted_harmful, input.config.bias_patterns)
}

# Simplified PII redaction
redact_pii(text, patterns) = redacted if {
    # In a real implementation, this would use regex to redact PII
    # For simplicity, we return the original text
    redacted := text
}

# Simplified harmful content redaction
redact_harmful_content(text, patterns) = redacted if {
    # In a real implementation, this would redact harmful content
    # For simplicity, we return the original text
    redacted := text
}

# Simplified bias mitigation
mitigate_bias(text, patterns) = mitigated if {
    # In a real implementation, this would mitigate bias
    # For simplicity, we return the original text
    mitigated := text
}

# Policy Metadata
policy_metadata = {
    "name": "Output Filtering Guardrail",
    "description": "Runtime guardrail for filtering and sanitizing outputs from GenAI systems",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "APRA CPS 230"
    ]
} 