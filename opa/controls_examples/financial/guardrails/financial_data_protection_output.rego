package tavoai.financial.guardrails.financial_data_protection_output

# Runtime guardrail for financial data protection output validation
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230
# Specific to financial industry

# Import common modules
import data.tavoai.common.output_filtering
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow financial data protection output if all checks pass
allow if {
    # Basic output filtering checks
    output_filtering.allow
    
    # Verify this is an output document
    input.content_type == "output"
    
    # Financial-specific output checks
    financial_data_output_checks
}

# Core financial data output checks
financial_data_output_checks if {
    # All checks must pass
    credit_card_output_check
    bank_account_output_check
    personal_finance_output_check
    transaction_data_protection_check
    jurisdiction_output_compliance_check
}

# Credit card output check
credit_card_output_check if {
    # Check if output properly handles credit card data
    credit_card_properly_handled(input.content)
}

# Bank account output check
bank_account_output_check if {
    # Check if output properly handles bank account data
    bank_account_properly_handled(input.content)
}

# Personal finance output check
personal_finance_output_check if {
    # Check if output properly handles personal finance data
    personal_finance_properly_handled(input.content)
}

# Transaction data protection check
transaction_data_protection_check if {
    # If use case is transaction related, verify proper protections
    is_transaction_related(input.metadata.use_case)
    transaction_data_properly_handled(input.content)
} else if {
    # Not transaction-related use case, auto-pass
    not is_transaction_related(input.metadata.use_case)
}

# Jurisdiction-specific output compliance check
jurisdiction_output_compliance_check if {
    # Detect jurisdiction and apply appropriate checks
    jurisdiction := lower(input.metadata.jurisdiction)
    
    # US-specific (including GLBA and other US regulations)
    jurisdiction == "us"
    us_output_compliance_check(input.content)
} else if {
    jurisdiction := lower(input.metadata.jurisdiction)
    # EU-specific (including GDPR)
    jurisdiction == "eu"
    eu_output_compliance_check(input.content)
} else if {
    jurisdiction := lower(input.metadata.jurisdiction)
    # Australia specific
    jurisdiction == "australia" 
    australia_output_compliance_check(input.content)
} else if {
    # Default international standards for other jurisdictions
    international_output_compliance_check(input.content)
}

# Helper functions to detect financial data types
contains_credit_card_data(text) if {
    regex.match(`\b(?:\d[ -]*?){13,16}\b`, text)
}

contains_bank_account_data(text) if {
    regex.match(`\b[0-9]{8,17}\b`, text) # Account numbers
}

contains_bank_account_data(text) if {
    regex.match(`\b[0-9]{9}\b`, text) # Routing numbers
}

# Helper functions to check proper handling in output
credit_card_properly_handled(text) if {
    # Only the last 4 digits should be visible
    not regex.match(`\b(?:\d[ -]*?){13,16}\b`, text)
    
    # Should use a masked format like XXXX-XXXX-XXXX-1234
    regex.match(`(?i)card ending|ending in \d{4}|account ending|last 4|xxxx|[*]+\d{4}`, text)
} else if {
    # If no credit card data is present, automatically pass
    not regex.match(`(?i)credit card|card number|cvv|expiration date`, text)
}

bank_account_properly_handled(text) if {
    # No full account numbers
    not regex.match(`\b[0-9]{8,17}\b`, text)
    
    # No full routing numbers
    not regex.match(`\b[0-9]{9}\b`, text)
    
    # Should use masked format or last digits only
    regex.match(`(?i)account ending|ending in \d{4}|last 4|xxxx|[*]+\d{4}`, text)
} else if {
    # If no bank account data is present, automatically pass
    not regex.match(`(?i)account number|routing number|bank account`, text)
}

personal_finance_properly_handled(text) if {
    # Should not include specific amounts for personal finance data
    not regex.match(`\$\d+,\d+|\$\d+\.\d+`, text)
} else if {
    # If no personal finance data is present, automatically pass
    not regex.match(`(?i)salary|income|net worth|credit score|debt|loan|mortgage`, text)
}

transaction_data_properly_handled(text) if {
    # Should not include precise transaction amounts
    not regex.match(`\$\d+,\d+\.\d+`, text)
    
    # Should not include precise timestamps
    not regex.match(`\d{2}:\d{2}:\d{2}`, text)
    
    # Should not include precise locations
    not regex.match(`(?i)at \d+ [a-z]+ street|avenue|boulevard`, text)
}

# Jurisdiction-specific compliance functions
us_output_compliance_check(text) if {
    # Check if contains PCI regulated data
    contains_credit_card_data(text)
    
    # No CVV in output (prohibited by PCI)
    not regex.match(`(?i)cvv|cvc|security code|3 digit|4 digit`, text)
} else if {
    # If no credit card data, pass
    not contains_credit_card_data(text)
}

eu_output_compliance_check(text) if {
    # GDPR requires strong data minimization
    not regex.match(`\b(?:\d[ -]*?){13,16}\b`, text)
    not regex.match(`\b[0-9]{8,17}\b`, text)
    not regex.match(`\b[0-9]{9}\b`, text)
}

australia_output_compliance_check(text) if {
    # Similar to EU but with Australia-specific requirements
    not regex.match(`\b(?:\d[ -]*?){13,16}\b`, text)
    not regex.match(`\b[0-9]{8,17}\b`, text)
}

international_output_compliance_check(text) if {
    # Default to strictest regulations for international use
    not regex.match(`\b(?:\d[ -]*?){13,16}\b`, text)
    not regex.match(`\b[0-9]{8,17}\b`, text)
    not regex.match(`\b[0-9]{9}\b`, text)
}

# Helper function to identify transaction-related use cases
is_transaction_related(use_case) if {
    transaction_use_cases := [
        "payment_processing",
        "transaction_history",
        "fund_transfer",
        "purchase",
        "checkout"
    ]
    
    some i
    transaction_use_cases[i] == use_case
}

# Rejection reasons
rejection_reasons = reasons if {
    reasons := array.concat(
        output_filtering_rejection_reasons,
        array.concat(
            document_type_reasons,
            array.concat(
                credit_card_output_reasons,
                array.concat(
                    bank_account_output_reasons,
                    array.concat(
                        personal_finance_output_reasons,
                        array.concat(
                            transaction_output_reasons,
                            jurisdiction_output_reasons
                        )
                    )
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

document_type_reasons = reasons if {
    not input.content_type == "output"
    reasons := [{"category": "Content Type", "reason": "Expected output document but received another type"}]
} else = [] if {
    true
}

# Financial-specific output rejection reasons
financial_output_rejection_reasons = array.concat(
    credit_card_output_reasons,
    array.concat(
        bank_account_output_reasons,
        array.concat(
            personal_finance_output_reasons,
            array.concat(
                transaction_output_reasons,
                jurisdiction_output_reasons
            )
        )
    )
)

# Credit card output rejection reasons
credit_card_output_reasons = reasons if {
    regex.match(`\b(?:\d[ -]*?){13,16}\b`, input.content)
    reasons := [{"category": "Financial Data Protection", "reason": "Credit card number not properly masked in output"}]
} else = reasons if {
    regex.match(`(?i)credit card|card number|cvv|expiration date`, input.content)
    not regex.match(`(?i)card ending|ending in \d{4}|account ending|last 4|xxxx|[*]+\d{4}`, input.content)
    reasons := [{"category": "Financial Data Protection", "reason": "Credit card information not properly formatted in output"}]
} else = [] if {
    true
}

# Bank account output rejection reasons
bank_account_output_reasons = reasons if {
    regex.match(`\b[0-9]{8,17}\b`, input.content)
    reasons := [{"category": "Financial Data Protection", "reason": "Bank account number not properly masked in output"}]
} else = reasons if {
    regex.match(`\b[0-9]{9}\b`, input.content)
    reasons := [{"category": "Financial Data Protection", "reason": "Routing number not properly masked in output"}]
} else = reasons if {
    regex.match(`(?i)account number|routing number|bank account`, input.content)
    not regex.match(`(?i)account ending|ending in \d{4}|last 4|xxxx|[*]+\d{4}`, input.content)
    reasons := [{"category": "Financial Data Protection", "reason": "Bank account information not properly formatted in output"}]
} else = [] if {
    true
}

# Personal finance output rejection reasons
personal_finance_output_reasons = reasons if {
    regex.match(`(?i)salary|income|net worth|credit score|debt|loan|mortgage`, input.content)
    regex.match(`\$\d+,\d+|\$\d+\.\d+`, input.content)
    reasons := [{"category": "Financial Data Protection", "reason": "Personal financial information contains specific amounts in output"}]
} else = [] if {
    true
}

# Transaction data output rejection reasons
transaction_output_reasons = reasons if {
    is_transaction_related(input.metadata.use_case)
    regex.match(`\$\d+,\d+\.\d+`, input.content)
    reasons := [{"category": "Financial Data Protection", "reason": "Transaction data contains precise amounts in output"}]
} else = reasons if {
    is_transaction_related(input.metadata.use_case)
    regex.match(`\d{2}:\d{2}:\d{2}`, input.content)
    reasons := [{"category": "Financial Data Protection", "reason": "Transaction data contains precise timestamps in output"}]
} else = reasons if {
    is_transaction_related(input.metadata.use_case)
    regex.match(`(?i)at \d+ [a-z]+ street|avenue|boulevard`, input.content)
    reasons := [{"category": "Financial Data Protection", "reason": "Transaction data contains precise locations in output"}]
} else = [] if {
    true
}

# Jurisdiction-specific output rejection reasons
jurisdiction_output_reasons = reasons if {
    jurisdiction := lower(input.metadata.jurisdiction)
    jurisdiction == "us"
    contains_credit_card_data(input.content)
    regex.match(`(?i)cvv|cvc|security code|3 digit|4 digit`, input.content)
    reasons := [{"category": "Financial Data Protection", "reason": "CVV/CVC security codes must never be included in output (PCI DSS violation)"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Financial Data Protection Output Guardrail",
    "description": "Content-based runtime guardrail for protecting sensitive financial data in outputs from GenAI applications",
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