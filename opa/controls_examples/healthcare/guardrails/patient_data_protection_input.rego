package tavoai.healthcare.guardrails.patient_data_protection_input

# Runtime guardrail for patient data protection input validation
# Based on EU AI Act, NIST AI RMF, HIPAA, GDPR and other privacy regulations
# Specific to healthcare industry

# Import common modules
import data.tavoai.common.input_validation
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow patient data input if all checks pass
allow if {
    # Basic validation checks
    input_validation.allow
    
    # Verify this is an input document
    input.content_type == "input"
    
    # Healthcare-specific patient data input checks
    patient_data_input_checks
}

# Core patient data input checks
patient_data_input_checks if {
    # Check if the input request is appropriate for patient data
    not contains_prohibited_patient_data_requests(input.content)
    
    # Check if configuration is appropriate for PHI
    phi_config_check
    
    # Additional checks for specific data types
    not contains_ssn_request(input.content)
    not contains_financial_info_request(input.content)
    
    # Ensure appropriate user authentication level for data access
    user_authentication_level_check
}

# Helper function to detect prohibited patient data requests
contains_prohibited_patient_data_requests(text) if {
    prohibited_patterns := [
        "(?i)show me (all|every|the|complete).{1,30}patient",
        "(?i)list.{1,30}(patient|medical).{1,30}record",
        "(?i)give me.{1,30}(patient|medical|health).{1,30}(data|information|details)",
        "(?i)access.{1,30}(patient|medical|health).{1,30}(data|information|details)"
    ]
    
    # Unless explicitly requesting de-identified or aggregated data
    not regex.match("(?i)(de-identified|anonymous|anonymized|aggregated|summary|statistics)", text)
    
    pattern := prohibited_patterns[_]
    regex.match(pattern, text)
}

# Helper function to detect SSN requests
contains_ssn_request(text) if {
    ssn_patterns := [
        "(?i)social security",
        "(?i)ssn",
        "(?i)tax.{1,10}(id|identification|number)",
        "(?i)government.{1,10}(id|identification|number)"
    ]
    
    pattern := ssn_patterns[_]
    regex.match(pattern, text)
}

# Helper function to detect financial information requests
contains_financial_info_request(text) if {
    financial_patterns := [
        "(?i)(credit|debit).{1,10}card",
        "(?i)bank.{1,10}account",
        "(?i)payment.{1,10}(details|information)",
        "(?i)billing.{1,10}(information|details)"
    ]
    
    pattern := financial_patterns[_]
    regex.match(pattern, text)
}

# Check if configuration is appropriate for PHI data
phi_config_check if {
    # For PHI content, PHI detection should be enabled
    input.config.phi_detection_enabled == true
    
    # For PHI content, HIPAA compliance checks should be enabled
    input.config.hipaa_compliance_enabled == true
}

# Check if user has appropriate authentication level
user_authentication_level_check if {
    # User must be authenticated to access patient data
    input.metadata.user.authenticated == true
    
    # User type must be authorized for clinical data
    authorized_types := ["clinician", "doctor", "nurse", "administrator", "researcher"]
    user_type := input.metadata.user.type
    authorized_types[_] == user_type
}

# Rejection reasons
rejection_reasons = reasons if {
    reasons := array.concat(
        input_validation_rejection_reasons,
        patient_data_input_rejection_reasons
    )
}

# Input validation rejection reasons
input_validation_rejection_reasons = reasons if {
    not input_validation.allow
    reasons := input_validation.rejection_reasons
} else = [] if {
    true
}

# Patient data input specific rejection reasons
patient_data_input_rejection_reasons = array.concat(
    document_type_reasons,
    array.concat(
        prohibited_request_reasons,
        array.concat(
            config_reasons,
            array.concat(
                data_type_reasons,
                auth_reasons
            )
        )
    )
)

document_type_reasons = reasons if {
    not input.content_type == "input"
    reasons := [{"category": "Content Type", "reason": "Expected input document but received another type"}]
} else = [] if {
    true
}

prohibited_request_reasons = reasons if {
    contains_prohibited_patient_data_requests(input.content)
    reasons := [{"category": "Patient Data", "reason": "Input contains requests for direct patient data which may violate privacy regulations"}]
} else = [] if {
    true
}

config_reasons = reasons if {
    not phi_config_check
    reasons := [{"category": "Configuration", "reason": "PHI detection and HIPAA compliance must be enabled for patient data requests"}]
} else = [] if {
    true
}

data_type_reasons = array.concat(ssn_reasons, financial_reasons)

ssn_reasons = reasons if {
    contains_ssn_request(input.content)
    reasons := [{"category": "Sensitive Data", "reason": "Requests for SSNs or government IDs are not permitted"}]
} else = [] if {
    true
}

financial_reasons = reasons if {
    contains_financial_info_request(input.content)
    reasons := [{"category": "Sensitive Data", "reason": "Requests for financial information are not permitted"}]
} else = [] if {
    true
}

auth_reasons = reasons if {
    not user_authentication_level_check
    reasons := [{"category": "Authentication", "reason": "User does not have appropriate authentication level for patient data access"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Patient Data Protection Input Guardrail",
    "description": "Input validation guardrail for patient data protection in GenAI applications",
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