package tavoai.financial.guardrails.financial_advice_output

# Runtime guardrail for financial advice output validation
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230
# Specific to financial industry

# Import common guardrails and pattern definitions
import data.tavoai.common.output_filtering
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow financial advice output if all checks pass
allow if {
    # Output filtering
    output_filtering.allow
    
    # Additional output-specific checks
    input.content_type == "output"  # Verify this is an output document
    
    # Financial advice specific checks
    advice_qualification_compliant
    advice_disclaimers_compliant
    advice_limitations_compliant
    advice_risk_disclosure_compliant
    advice_regulatory_compliant
}

# Advice qualification check
advice_qualification_compliant if {
    # Check if advice is qualified - content-based approach
    advice_type := categorize_advice(input.content)
    is_qualified_for_advice_type(advice_type, input.content)
}

# Advice disclaimers check
advice_disclaimers_compliant if {
    # Check if all required disclaimers are included
    contains_generic_financial_disclaimer(input.content)
}

# Advice limitations check
advice_limitations_compliant if {
    # Check if appropriate limitations are mentioned
    contains_advice_limitations(input.content)
}

# Risk disclosure check
advice_risk_disclosure_compliant if {
    # Check if risks are properly disclosed
    contains_risk_disclosure(input.content)
}

# Regulatory compliance check
advice_regulatory_compliant if {
    # Check jurisdiction-specific regulatory compliance
    jurisdiction := lower(input.metadata.jurisdiction)
    jurisdiction_compliant(jurisdiction, input.content)
}

# Helper function to categorize financial advice
categorize_advice(text) = advice_type if {
    contains_investment_advice(text)
    advice_type := "investment"
} else = advice_type if {
    contains_retirement_advice(text)
    advice_type := "retirement"
} else = advice_type if {
    contains_tax_advice(text)
    advice_type := "tax"
} else = advice_type if {
    contains_debt_advice(text)
    advice_type := "debt"
} else = advice_type if {
    contains_insurance_advice(text)
    advice_type := "insurance"
} else = advice_type if {
    advice_type := "general"
}

# Helper functions to identify different types of advice
contains_investment_advice(text) if {
    investment_terms := [
        "investment", "stock", "bond", "mutual fund", "etf", 
        "portfolio", "asset allocation", "diversification"
    ]
    term := investment_terms[_]
    contains(lower(text), term)
}

contains_retirement_advice(text) if {
    retirement_terms := [
        "retirement", "pension", "401k", "ira", "superannuation",
        "annuity", "social security"
    ]
    term := retirement_terms[_]
    contains(lower(text), term)
}

contains_tax_advice(text) if {
    tax_terms := [
        "tax", "deduction", "credit", "write-off", "capital gains",
        "irs", "filing", "return"
    ]
    term := tax_terms[_]
    contains(lower(text), term)
}

contains_debt_advice(text) if {
    debt_terms := [
        "debt", "loan", "mortgage", "credit card", "interest rate",
        "refinance", "consolidation", "bankruptcy"
    ]
    term := debt_terms[_]
    contains(lower(text), term)
}

contains_insurance_advice(text) if {
    insurance_terms := [
        "insurance", "policy", "premium", "coverage", "deductible",
        "claim", "underwriting", "risk management"
    ]
    term := insurance_terms[_]
    contains(lower(text), term)
}

# Check if content is qualified to provide advice
is_qualified_for_advice_type(advice_type, text) if {
    qualification_patterns := [
        "(?i)general (information|advice)",
        "(?i)not (personalized|individual) (advice|recommendation)",
        "(?i)consult.{1,30}(financial|professional) (advisor|adviser)",
        "(?i)not a substitute for professional financial advice"
    ]
    
    pattern := qualification_patterns[_]
    regex.match(pattern, text)
}

# Check for generic financial disclaimer
contains_generic_financial_disclaimer(text) if {
    disclaimer_patterns := [
        "(?i)past performance is not (indicative|guarantee)",
        "(?i)investment involves risk",
        "(?i)value.{1,30}(go down|decrease|fluctuate)",
        "(?i)consult.{1,30}professional financial advisor",
        "(?i)not (financial|investment|tax|professional) advice"
    ]
    
    pattern := disclaimer_patterns[_]
    regex.match(pattern, text)
}

# Check for advice limitations
contains_advice_limitations(text) if {
    limitation_patterns := [
        "(?i)based on (limited|general) information",
        "(?i)individual circumstances (may|will) vary",
        "(?i)depends on your (specific|personal|individual) (situation|circumstances)",
        "(?i)should consider your (objectives|needs|situation)"
    ]
    
    pattern := limitation_patterns[_]
    regex.match(pattern, text)
}

# Check for risk disclosure
contains_risk_disclosure(text) if {
    risk_patterns := [
        "(?i)risk (of|to) (capital|principal|investment)",
        "(?i)may (lose|result in loss|decline in value)",
        "(?i)investment involves risk",
        "(?i)no guarantee of (return|profit)",
        "(?i)value.{1,30}(go down|decrease|fluctuate)"
    ]
    
    pattern := risk_patterns[_]
    regex.match(pattern, text)
}

# Check jurisdiction-specific compliance
jurisdiction_compliant(jurisdiction, text) if {
    jurisdiction == "us"
    us_compliant(text)
} else if {
    jurisdiction == "eu"
    eu_compliant(text)
} else if {
    jurisdiction == "australia"
    australia_compliant(text)
} else if {
    # Default international compliance
    contains_generic_financial_disclaimer(text)
}

# US-specific compliance
us_compliant(text) if {
    contains_generic_financial_disclaimer(text)
}

# EU-specific compliance
eu_compliant(text) if {
    contains_generic_financial_disclaimer(text)
    contains_risk_disclosure(text)
}

# Australia-specific compliance
australia_compliant(text) if {
    australia_disclaimer_patterns := [
        "(?i)general advice only",
        "(?i)not taken into account your (objectives|needs|situation)",
        "(?i)financial product",
        "(?i)australian financial services"
    ]
    
    pattern := australia_disclaimer_patterns[_]
    regex.match(pattern, text)
}

# Rejection Reasons
rejection_reasons = reasons if {
    reasons := array.concat(
        output_filtering_rejection_reasons,
        financial_output_rejection_reasons
    )
}

# Output filtering rejection reasons
output_filtering_rejection_reasons = reasons if {
    not output_filtering.allow
    reasons := output_filtering.rejection_reasons
} else = [] if {
    true
}

# Define reasons based on compliance checks, providing default empty lists
qualification_reasons = reasons if {
    not advice_qualification_compliant
    reasons := [{"category": "Qualification", "reason": "Advice qualification requirements not met"}]
} else = [] if { true }

disclaimer_reasons = reasons if {
    not advice_disclaimers_compliant
    reasons := [{"category": "Disclaimers", "reason": "Required disclaimers are missing"}]
} else = [] if { true }

limitations_reasons = reasons if {
    not advice_limitations_compliant
    reasons := [{"category": "Limitations", "reason": "Advice limitations are not properly stated"}]
} else = [] if { true }

risk_reasons = reasons if {
    not advice_risk_disclosure_compliant
    reasons := [{"category": "Risk Disclosure", "reason": "Risk disclosures are inadequate or missing"}]
} else = [] if { true }

regulatory_reasons = reasons if {
    not advice_regulatory_compliant
    reasons := [{"category": "Regulatory", "reason": "Jurisdiction-specific regulatory requirements not met"}]
} else = [] if { true }

# Financial output specific rejection reasons
# Use array.concat to combine the reason lists, not '+'
financial_output_rejection_reasons = array.concat(
    array.concat(
        array.concat(
            array.concat(
                array.concat(document_type_reasons, qualification_reasons),
                disclaimer_reasons),
            limitations_reasons),
        risk_reasons),
    regulatory_reasons
)

document_type_reasons = reasons if {
    not input.content_type == "output"
    reasons := [{"category": "Content Type", "reason": "Expected output document but received another type"}]
} else = [] if {
    true
}