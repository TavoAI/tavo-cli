package tavoai.financial.guardrails.financial_data_protection_input

# Runtime guardrail for financial data protection input validation
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230
# Specific to financial industry

# Import common modules
import data.tavoai.common.input_validation
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow financial data protection input if all checks pass
allow if {
    # Basic validation checks
    input_validation.allow
    
    # Verify this is an input document
    input.content_type == "input"
    
    # Financial-specific input checks
    financial_data_input_checks
}

# Core financial data input checks
financial_data_input_checks if {
    # All checks must pass
    credit_card_input_check
    bank_account_input_check
    personal_finance_input_check
    jurisdiction_input_compliance_check
}

# Credit card input check
credit_card_input_check if {
    # If credit card data detected, check if handling is appropriate based on config
    contains_credit_card_data(input.content)
    
    # Check if configuration allows credit card data
    input.config.credit_card_data_allowed == true
} else if {
    # No credit card data detected, automatically pass
    not contains_credit_card_data(input.content)
}

# Bank account input check
bank_account_input_check if {
    # If bank account data detected, check if handling is appropriate based on config
    contains_bank_account_data(input.content)
    
    # Check if configuration allows bank account data
    input.config.bank_account_data_allowed == true
} else if {
    # No bank account data detected, automatically pass
    not contains_bank_account_data(input.content)
}

# Personal finance input check
personal_finance_input_check if {
    # If personal finance data detected, ensure appropriate handling
    contains_personal_finance_data(input.content)
    
    # Check if configuration allows personal finance data
    input.config.personal_finance_data_allowed == true
} else if {
    # No personal finance data detected, automatically pass
    not contains_personal_finance_data(input.content)
}

# Jurisdiction-specific input compliance check
jurisdiction_input_compliance_check if {
    # Detect jurisdiction and apply appropriate checks
    jurisdiction := lower(input.metadata.jurisdiction)
    
    # US-specific (including GLBA and other US regulations)
    jurisdiction == "us"
    us_input_compliance_check(input.content)
} else if {
    jurisdiction := lower(input.metadata.jurisdiction)
    # EU-specific (including GDPR)
    jurisdiction == "eu"
    eu_input_compliance_check(input.content)
} else if {
    jurisdiction := lower(input.metadata.jurisdiction)
    # Australia specific
    jurisdiction == "australia" 
    australia_input_compliance_check(input.content)
} else if {
    # Default international standards for other jurisdictions
    international_input_compliance_check(input.content)
}

# Helper functions to detect financial data types
contains_credit_card_data(text) if {
    regex.match(`\b(?:\d[ -]*?){13,16}\b`, text)
}

contains_credit_card_data(text) if {
    regex.match(`(?i)credit card|card number|cvv|expiration date`, text)
}

contains_bank_account_data(text) if {
    regex.match(`\b[0-9]{8,17}\b`, text) # Account numbers
}

contains_bank_account_data(text) if {
    regex.match(`\b[0-9]{9}\b`, text) # Routing numbers
}

contains_bank_account_data(text) if {
    regex.match(`(?i)account number|routing number|bank account`, text)
}

contains_personal_finance_data(text) if {
    regex.match(`(?i)salary|income|net worth|credit score|debt|loan|mortgage`, text)
}

# Jurisdiction-specific compliance functions for input
us_input_compliance_check(text) if {
    # Check if contains restricted financial PII
    contains_financial_pii(text)
    
    # Ensure appropriate consent is obtained
    input.config.financial_pii_consent_obtained == true
}

us_input_compliance_check(text) if {
    # No financial PII detected
    not contains_financial_pii(text)
}

eu_input_compliance_check(text) if {
    # GDPR-specific checks
    contains_financial_pii(text)
    
    # Must have explicit consent for data processing
    input.config.gdpr_explicit_consent == true
}

eu_input_compliance_check(text) if {
    # No financial PII detected
    not contains_financial_pii(text)
}

australia_input_compliance_check(text) if {
    # Australia-specific checks
    true
}

international_input_compliance_check(text) if {
    # Default international standards
    true
}

# Helper function to detect financial PII
contains_financial_pii(text) if {
    contains_credit_card_data(text)
}

contains_financial_pii(text) if {
    contains_bank_account_data(text)
}

contains_financial_pii(text) if {
    regex.match(`(?i)tax.{1,20}(id|identification|number)`, text)
}

# Rejection reasons
rejection_reasons = reasons if {
    reasons := array.concat(
        input_validation_rejection_reasons,
        array.concat(
            document_type_reasons,
            financial_data_input_rejection_reasons
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

document_type_reasons = reasons if {
    not input.content_type == "input"
    reasons := [{"category": "Content Type", "reason": "Expected input document but received another type"}]
} else = [] if {
    true
}

# Financial data input specific rejection reasons
financial_data_input_rejection_reasons = array.concat(
    credit_card_input_reasons,
    array.concat(
        bank_account_input_reasons,
        array.concat(
            personal_finance_input_reasons,
            jurisdiction_input_reasons
        )
    )
)

# Credit card input rejection reasons
credit_card_input_reasons = reasons if {
    contains_credit_card_data(input.content)
    not input.config.credit_card_data_allowed == true
    reasons := [{"category": "Financial Data Protection", "reason": "Credit card information not allowed in input based on configuration"}]
} else = [] if {
    true
}

# Bank account input rejection reasons
bank_account_input_reasons = reasons if {
    contains_bank_account_data(input.content)
    not input.config.bank_account_data_allowed == true
    reasons := [{"category": "Financial Data Protection", "reason": "Bank account information not allowed in input based on configuration"}]
} else = [] if {
    true
}

# Personal finance input rejection reasons
personal_finance_input_reasons = reasons if {
    contains_personal_finance_data(input.content)
    not input.config.personal_finance_data_allowed == true
    reasons := [{"category": "Financial Data Protection", "reason": "Personal financial information not allowed in input based on configuration"}]
} else = [] if {
    true
}

# Jurisdiction-specific input rejection reasons
jurisdiction_input_reasons = array.concat(us_input_reasons, eu_input_reasons)

us_input_reasons = reasons if {
    jurisdiction := lower(input.metadata.jurisdiction)
    jurisdiction == "us"
    contains_financial_pii(input.content)
    not input.config.financial_pii_consent_obtained == true
    reasons := [{"category": "Financial Data Protection", "reason": "Financial PII detected in US context without proper consent (GLBA violation)"}]
} else = [] if {
    true
}

eu_input_reasons = reasons if {
    jurisdiction := lower(input.metadata.jurisdiction)
    jurisdiction == "eu"
    contains_financial_pii(input.content)
    not input.config.gdpr_explicit_consent == true
    reasons := [{"category": "Financial Data Protection", "reason": "Financial PII detected in EU context without explicit GDPR consent"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Financial Data Protection Input Guardrail",
    "description": "Content-based runtime guardrail for protecting sensitive financial data in inputs to GenAI applications",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "APRA CPS 230",
        "PCI DSS",
        "GLBA",
        "GDPR",
        "CCPA"
    ]
} 