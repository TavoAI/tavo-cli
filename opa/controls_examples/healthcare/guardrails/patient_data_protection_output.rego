package tavoai.healthcare.guardrails.patient_data_protection_output

# Runtime guardrail for patient data protection output validation
# Based on EU AI Act, NIST AI RMF, HIPAA, GDPR and other privacy regulations
# Specific to healthcare industry

# Import common modules
import data.tavoai.common.output_filtering
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow patient data output if all checks pass
allow if {
    # Basic output validation checks
    output_filtering.allow
    
    # Verify this is an output document
    input.content_type == "output"
    
    # Healthcare-specific output checks
    patient_data_output_checks
}

# Core patient data output checks
patient_data_output_checks if {
    # Check if the output properly de-identifies patient data
    not contains_patient_identifiers(input.content)
    
    # Check if the output includes appropriate disclaimers
    contains_data_protection_disclaimers(input.content)
    
    # Check if the output is compliant with healthcare privacy laws
    privacy_compliance_check
}

# Helper function to detect patient identifiers
contains_patient_identifiers(text) if {
    patient_identifier_patterns := [
        "(?i)Patient\\s+(ID|Number|#):\\s*[A-Za-z0-9\\-]+",
        "(?i)MRN\\s*[#:]?\\s*[A-Za-z0-9\\-]+",
        "(?i)Record\\s+(ID|Number|#):\\s*[A-Za-z0-9\\-]+",
        "(?i)SSN\\s*[#:]?\\s*[\\d\\-]+",
        "(?i)(\\d{3}-\\d{2}-\\d{4})",  # SSN format
        "(?i)(\\d{3}-\\d{3}-\\d{4})",  # Phone number format
        "(?i)([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})",  # Email format
        "(?i)DOB\\s*[:]?\\s*\\d{1,2}[/-]\\d{1,2}[/-]\\d{2,4}"  # Date of birth
    ]
    
    pattern := patient_identifier_patterns[_]
    regex.match(pattern, text)
}

# Helper function to check for data protection disclaimers
contains_data_protection_disclaimers(text) if {
    disclaimer_patterns := [
        "(?i)(data|information).{1,30}(de-identified|anonymized)",
        "(?i)no.{1,20}(personal|identifiable).{1,20}information",
        "(?i)(compliant|compliance).{1,20}(with|to).{1,20}(HIPAA|privacy)",
        "(?i)(privacy|confidentiality).{1,20}protected"
    ]
    
    pattern := disclaimer_patterns[_]
    regex.match(pattern, text)
}

# Privacy compliance check
privacy_compliance_check if {
    # Get jurisdiction from metadata
    jurisdiction := input.metadata.jurisdiction
    
    # Apply jurisdiction-specific rules
    jurisdiction_specific_compliance(jurisdiction, input.content)
}

# US-specific compliance (HIPAA)
jurisdiction_specific_compliance("US", text) if {
    # HIPAA compliance - check for any PHI
    not contains_phi(text)
} else if {
    # If there is aggregate data, ensure it's properly de-identified
    contains_aggregate_data(text)
    contains_hipaa_safe_harbor_statement(text)
}

# EU-specific compliance (GDPR)
jurisdiction_specific_compliance("EU", text) if {
    # GDPR compliance
    not contains_personal_data(text)
} else if {
    # If there is personal data, ensure it's anonymized
    contains_personal_data(text)
    contains_gdpr_anonymization_statement(text)
}

# Australia-specific compliance
jurisdiction_specific_compliance("Australia", text) if {
    # Australian Privacy Act compliance
    not contains_personal_information(text)
} else if {
    # If there is personal information, ensure proper disclaimers
    contains_personal_information(text)
    contains_australian_privacy_statement(text)
}

# Default jurisdiction compliance (when not US, EU, or Australia)
jurisdiction_specific_compliance(jurisdiction, text) if {
    # Default privacy compliance check for other jurisdictions
    not contains_patient_identifiers(text)
}

# Helper functions for jurisdiction-specific compliance

# Check for PHI (Protected Health Information)
contains_phi(text) if {
    phi_patterns := [
        "(?i)name\\s*[:]\\s*[A-Za-z\\s\\.]+",
        "(?i)address\\s*[:]\\s*.+",
        "(?i)(medical|health)\\s+record\\s*[#:]\\s*[A-Za-z0-9\\-]+",
        "(?i)patient\\s+[A-Za-z0-9\\-]+"  # Patient followed by what could be an identifier
    ]
    
    pattern := phi_patterns[_]
    regex.match(pattern, text)
}

# Check for aggregate data
contains_aggregate_data(text) if {
    aggregate_patterns := [
        "(?i)(total|sum|count|average|mean|median)\\s+of\\s+patients",
        "(?i)(\\d+)\\s+patients",
        "(?i)patient\\s+population",
        "(?i)(statistical|aggregate|summary)\\s+(data|analysis|report)",
        "(?i)(percentage|proportion)\\s+of\\s+patients"
    ]
    
    pattern := aggregate_patterns[_]
    regex.match(pattern, text)
}

# Check for HIPAA Safe Harbor statement
contains_hipaa_safe_harbor_statement(text) if {
    regex.match("(?i)(compliant|compliance|accordance).{1,30}(with|to).{1,30}HIPAA.{1,30}(Safe Harbor|de-identification)", text)
}

# Check for personal data (GDPR context)
contains_personal_data(text) if {
    personal_data_patterns := [
        "(?i)individual\\s+patient",
        "(?i)specific\\s+person",
        "(?i)patient\\s+(named|identified\\s+as)",
        "(?i)patient's\\s+(information|data|details)"
    ]
    
    pattern := personal_data_patterns[_]
    regex.match(pattern, text)
}

# Check for GDPR anonymization statement
contains_gdpr_anonymization_statement(text) if {
    regex.match("(?i)(compliant|compliance|accordance).{1,30}(with|to).{1,30}(GDPR|EU).{1,30}(anonymization|data protection)", text)
}

# Check for personal information (Australian context)
contains_personal_information(text) if {
    # Similar to personal data patterns but with Australian context
    regex.match("(?i)(individual|specific).{1,20}(patient|person)", text)
}

# Check for Australian privacy statement
contains_australian_privacy_statement(text) if {
    regex.match("(?i)(compliant|compliance|accordance).{1,30}(with|to).{1,30}(Australian Privacy Act|Privacy Principles)", text)
}

# Rejection reasons
rejection_reasons = reasons if {
    reasons := array.concat(
        output_filtering_rejection_reasons,
        array.concat(
            document_type_reasons,
            array.concat(
                identifier_reasons,
                array.concat(
                    disclaimer_reasons,
                    privacy_reasons
                )
            )
        )
    )
}

# Output filtering rejection reasons
output_filtering_rejection_reasons = reasons if {
    not output_filtering.allow
    reasons := output_filtering.rejection_reasons
} else = [] if {
    true
}

# Patient data output specific rejection reasons
document_type_reasons = reasons if {
    not input.content_type == "output"
    reasons := [{"category": "Content Type", "reason": "Expected output document but received another type"}]
} else = [] if {
    true
}

identifier_reasons = reasons if {
    contains_patient_identifiers(input.content)
    reasons := [{"category": "Patient Identifiers", "reason": "Output contains patient identifiers that should be removed or de-identified"}]
} else = [] if {
    true
}

disclaimer_reasons = reasons if {
    not contains_data_protection_disclaimers(input.content)
    reasons := [{"category": "Data Protection", "reason": "Output is missing required data protection disclaimers"}]
} else = [] if {
    true
}

privacy_reasons = reasons if {
    not privacy_compliance_check
    reasons := [{"category": "Privacy Compliance", "reason": "Output does not comply with privacy regulations for the specified jurisdiction"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Patient Data Protection Output Guardrail",
    "description": "Output validation guardrail for patient data protection in GenAI applications",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "HIPAA",
        "GDPR",
        "California CMIA",
        "Australian Privacy Act",
        "Health Records Act"
    ]
} 