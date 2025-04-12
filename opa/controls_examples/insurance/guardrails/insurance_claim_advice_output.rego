package tavoai.insurance.guardrails.insurance_claim_advice_output

# Runtime guardrail for insurance claim advice output validation
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230
# Specific to insurance industry

# Import common modules
import data.tavoai.common.output_filtering
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow insurance claim advice output if all checks pass
allow if {
    # Basic output validation checks
    output_filtering.allow
    
    # Verify this is an output document
    input.content_type == "output"
    
    # Insurance-specific output checks
    insurance_claim_advice_output_checks
}

# Core insurance claim advice output checks
insurance_claim_advice_output_checks if {
    # Check if the advice is properly qualified
    advice_qualification_check(input.content)
    
    # Check if the advice includes appropriate disclaimers
    disclaimer_check(input.content)
    
    # Check if the advice mentions limitations
    limitations_check(input.content)
    
    # Check if the advice is factually accurate
    not contains_misinformation(input.content)
    
    # Check for jurisdiction compliance
    jurisdiction_compliance_check
}

# Check for advice qualification
advice_qualification_check(text) if {
    # Advice should avoid making specific guarantees
    not contains_guarantees(text)
    
    # Advice should acknowledge claim assessment process
    contains_assessment_process(text)
}

# Check for appropriate disclaimers
disclaimer_check(text) if {
    # Advice should include appropriate disclaimers
    contains_general_disclaimers(text)
    contains_specific_disclaimers(text)
}

# Check for mentioning limitations
limitations_check(text) if {
    # Advice should mention policy-specific limitations
    contains_policy_limitations(text)
}

# Jurisdiction compliance check
jurisdiction_compliance_check if {
    # Get jurisdiction from metadata
    jurisdiction := input.metadata.jurisdiction
    
    # Apply jurisdiction-specific rules
    jurisdiction_specific_compliance(jurisdiction, input.content)
}

# Helper function to detect guarantees
contains_guarantees(text) if {
    guarantee_patterns := [
        "(?i)guarantee.{1,30}(approval|payout|settlement)",
        "(?i)promise.{1,30}(cover|payment|outcome)",
        "(?i)definitely.{1,30}(approved|paid|covered)",
        "(?i)certainly.{1,30}(eligible|qualify)",
        "(?i)ensure.{1,30}(payment|settlement|outcome)"
    ]
    
    pattern := guarantee_patterns[_]
    regex.match(pattern, text)
}

# Helper function to check for assessment process
contains_assessment_process(text) if {
    assessment_patterns := [
        "(?i)(claim|assessment) process",
        "(?i)(review|evaluate|assess).{1,30}claim",
        "(?i)(insurer|company|provider).{1,30}(review|evaluate|assess)",
        "(?i)documentation.{1,30}(required|needed|necessary)",
        "(?i)(policy|coverage).{1,30}(terms|conditions|provisions)"
    ]
    
    pattern := assessment_patterns[_]
    regex.match(pattern, text)
}

# Helper function to check for general disclaimers
contains_general_disclaimers(text) if {
    general_disclaimer_patterns := [
        "(?i)general.{1,30}(information|advice|guidance)",
        "(?i)not.{1,30}(substitute|replacement).{1,30}(professional|expert|legal).{1,30}(advice|guidance)",
        "(?i)consult.{1,30}(insurance|professional|advisor)",
        "(?i)specific.{1,30}circumstances.{1,30}(may|can|might).{1,30}(vary|differ)",
        "(?i)not.{1,30}(constitute|provide|offer).{1,30}(legal|binding|official)"
    ]
    
    pattern := general_disclaimer_patterns[_]
    regex.match(pattern, text)
}

# Helper function to check for specific disclaimers
contains_specific_disclaimers(text) if {
    specific_disclaimer_patterns := [
        "(?i)actual.{1,30}(coverage|payment|settlement).{1,30}(depend|based|determined)",
        "(?i)(terms|conditions).{1,30}(your|specific|individual).{1,30}policy",
        "(?i)(exclusions|limitations).{1,30}(may|might|could).{1,30}apply",
        "(?i)(final|ultimate).{1,30}decision.{1,30}(made|determined|rests)",
        "(?i)review.{1,30}(policy|documentation|terms)"
    ]
    
    pattern := specific_disclaimer_patterns[_]
    regex.match(pattern, text)
}

# Helper function to check for policy limitations
contains_policy_limitations(text) if {
    limitation_patterns := [
        "(?i)(coverage|policy).{1,30}limit",
        "(?i)(exclusion|limitation|restriction)",
        "(?i)(waiting|qualifying).{1,30}period",
        "(?i)(deductible|excess)",
        "(?i)pre-existing.{1,30}condition",
        "(?i)not.{1,30}all.{1,30}(claims|situations).{1,30}covered"
    ]
    
    pattern := limitation_patterns[_]
    regex.match(pattern, text)
}

# Helper function to detect misinformation
contains_misinformation(text) if {
    misinformation_patterns := [
        "(?i)all.{1,30}(claims|damages).{1,30}(covered|approved)",
        "(?i)no.{1,30}(exclusions|limitations|restrictions)",
        "(?i)always.{1,30}(approved|accepted|paid)",
        "(?i)never.{1,30}(denied|rejected|refused)",
        "(?i)regardless.{1,30}(circumstances|conditions|terms)",
        "(?i)bypass.{1,30}(process|investigation|assessment)"
    ]
    
    pattern := misinformation_patterns[_]
    regex.match(pattern, text)
}

# US-specific compliance
jurisdiction_specific_compliance("US", text) if {
    # US insurance compliance
    contains_us_insurance_compliance(text)
}

# EU-specific compliance
jurisdiction_specific_compliance("EU", text) if {
    # EU insurance compliance
    contains_eu_insurance_compliance(text)
}

# Australia-specific compliance
jurisdiction_specific_compliance("Australia", text) if {
    # Australian insurance compliance
    contains_au_insurance_compliance(text)
}

# Default jurisdiction compliance (when not US, EU, or Australia)
jurisdiction_specific_compliance(jurisdiction, text) if {
    # Default compliance check for other jurisdictions
    contains_general_disclaimers(text)
}

# Helper functions for jurisdiction-specific compliance

# Check for US insurance compliance
contains_us_insurance_compliance(text) if {
    us_compliance_patterns := [
        "(?i)(state|local).{1,30}(laws|regulations).{1,30}(may|might|could).{1,30}(vary|differ|apply)",
        "(?i)(different|various).{1,30}states.{1,30}(different|various).{1,30}(laws|regulations|requirements)",
        "(?i)consult.{1,30}(state insurance|department of insurance)",
        "(?i)specific.{1,30}state.{1,30}(laws|regulations).{1,30}apply"
    ]
    
    pattern := us_compliance_patterns[_]
    regex.match(pattern, text)
}

# Check for EU insurance compliance
contains_eu_insurance_compliance(text) if {
    eu_compliance_patterns := [
        "(?i)(EU|European Union).{1,30}(directives|regulations)",
        "(?i)(GDPR|General Data Protection Regulation)",
        "(?i)EU.{1,30}(consumer|policyholder).{1,30}(rights|protections)",
        "(?i)European Insurance.{1,30}Occupational Pensions Authority"
    ]
    
    pattern := eu_compliance_patterns[_]
    regex.match(pattern, text)
}

# Check for Australian insurance compliance
contains_au_insurance_compliance(text) if {
    au_compliance_patterns := [
        "(?i)(ASIC|Australian Securities and Investments Commission)",
        "(?i)Financial Services Guide",
        "(?i)Product Disclosure Statement",
        "(?i)Australian Financial Complaints Authority",
        "(?i)General Insurance Code of Practice"
    ]
    
    pattern := au_compliance_patterns[_]
    regex.match(pattern, text)
}

# Rejection reasons
rejection_reasons = reasons if {
    reasons := array.concat(
        output_filtering_rejection_reasons,
        array.concat(
            document_type_reasons,
            array.concat(
                advice_qualification_reasons,
                array.concat(
                    disclaimer_reasons,
                    array.concat(
                        limitation_reasons,
                        array.concat(
                            misinformation_reasons,
                            jurisdiction_reasons
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

# Document type rejection reasons
document_type_reasons = reasons if {
    not input.content_type == "output"
    reasons := [{"category": "Content Type", "reason": "Expected output document but received another type"}]
} else = [] if {
    true
}

# Advice qualification rejection reasons
advice_qualification_reasons = array.concat(
    guarantee_reasons,
    assessment_reasons
)

guarantee_reasons = reasons if {
    contains_guarantees(input.content)
    reasons := [{"category": "Advice Qualification", "reason": "Output contains inappropriate guarantees about claim outcomes"}]
} else = [] if {
    true
}

assessment_reasons = reasons if {
    not contains_assessment_process(input.content)
    reasons := [{"category": "Advice Qualification", "reason": "Output does not acknowledge the claim assessment process"}]
} else = [] if {
    true
}

# Disclaimer rejection reasons
disclaimer_reasons = array.concat(
    general_disclaimer_reasons,
    specific_disclaimer_reasons
)

general_disclaimer_reasons = reasons if {
    not contains_general_disclaimers(input.content)
    reasons := [{"category": "Disclaimers", "reason": "Output is missing general disclaimers about the advice provided"}]
} else = [] if {
    true
}

specific_disclaimer_reasons = reasons if {
    not contains_specific_disclaimers(input.content)
    reasons := [{"category": "Disclaimers", "reason": "Output is missing specific disclaimers about policy terms and conditions"}]
} else = [] if {
    true
}

# Limitation rejection reasons
limitation_reasons = reasons if {
    not contains_policy_limitations(input.content)
    reasons := [{"category": "Limitations", "reason": "Output does not mention policy limitations or exclusions"}]
} else = [] if {
    true
}

# Misinformation rejection reasons
misinformation_reasons = reasons if {
    contains_misinformation(input.content)
    reasons := [{"category": "Misinformation", "reason": "Output contains insurance misinformation or misleading statements"}]
} else = [] if {
    true
}

# Jurisdiction rejection reasons
jurisdiction_reasons = reasons if {
    not jurisdiction_compliance_check
    reasons := [{"category": "Jurisdiction Compliance", "reason": "Output does not comply with jurisdiction-specific insurance regulations"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Insurance Claim Advice Output Guardrail",
    "description": "Output validation guardrail for insurance claim advice in GenAI applications",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "APRA CPS 230",
        "ASIC RG 271",
        "State Insurance Regulatory Guidelines",
        "General Insurance Code of Practice"
    ]
} 