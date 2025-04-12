package tavoai.superannuation.guardrails.retirement_advice_output

# Runtime guardrail for retirement advice output validation
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230
# Specific to retirement and superannuation industry

# Import common modules
import data.tavoai.common.output_filtering
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow retirement advice output if all checks pass
allow if {
    # Basic output validation checks
    output_filtering.allow
    
    # Verify this is an output document
    input.content_type == "output"
    
    # Superannuation-specific output checks
    retirement_advice_output_checks
}

# Core retirement advice output checks
retirement_advice_output_checks if {
    # Check if the output meets best interest obligations
    best_interest_check(input.content)
    
    # Check if the output is within appropriate advice scope
    advice_scope_check(input.content)
    
    # Check if the output includes required disclosures
    disclosure_check(input.content)
    
    # Check if the output includes appropriate disclaimers
    disclaimer_check(input.content)
    
    # Check for compliance with jurisdiction-specific regulations
    regulatory_compliance_check
}

# Best interest check for retirement advice
best_interest_check(text) if {
    # Check if advice considers client's best interests
    contains_client_goals_consideration(text)
    contains_risk_assessment(text)
    not contains_prohibited_advice(text)
}

# Advice scope check for retirement advice
advice_scope_check(text) if {
    # Determine what type of advice is being provided
    is_investment_advice(text)
    investment_advice_scope_check(text)
} else if {
    is_contribution_advice(text)
    contribution_advice_scope_check(text)
} else if {
    is_benefit_access_advice(text)
    benefit_access_scope_check(text)
} else if {
    is_retirement_planning_advice(text)
    retirement_planning_scope_check(text)
} else if {
    is_fund_selection_advice(text)
    fund_selection_scope_check(text)
} else if {
    # If not one of the specific types, apply general scope check
    general_retirement_advice_scope_check(text)
}

# Disclosure check for retirement advice
disclosure_check(text) if {
    # Check for required disclosures based on advice type
    required_disclosure_check(text)
    risk_disclosure_check(text)
    fees_and_costs_disclosure_check(text)
}

# Disclaimer check for retirement advice
disclaimer_check(text) if {
    # Check for appropriate disclaimers
    general_disclaimer_check(text)
    specific_disclaimer_check(text)
    professional_advice_referral_check(text)
}

# Regulatory compliance check for retirement advice
regulatory_compliance_check if {
    # Get jurisdiction from metadata
    jurisdiction := input.metadata.jurisdiction
    
    # Apply jurisdiction-specific compliance checks
    jurisdiction_specific_compliance(jurisdiction, input.content)
}

# Helper functions to categorize retirement advice

# Check if advice is investment-related
is_investment_advice(text) if {
    investment_patterns := [
        "(?i)invest(ing|ment)",
        "(?i)asset allocation",
        "(?i)portfolio",
        "(?i)diversif(y|ication)",
        "(?i)(stocks|shares|bonds|equities)"
    ]
    
    pattern := investment_patterns[_]
    regex.match(pattern, text)
}

# Check if advice is contribution-related
is_contribution_advice(text) if {
    contribution_patterns := [
        "(?i)contribution",
        "(?i)(salary |concessional |non-concessional )sacrifice",
        "(?i)super guarantee",
        "(?i)catch-up contributions",
        "(?i)(pre|post)-tax contributions"
    ]
    
    pattern := contribution_patterns[_]
    regex.match(pattern, text)
}

# Check if advice is benefit access-related
is_benefit_access_advice(text) if {
    access_patterns := [
        "(?i)withdraw",
        "(?i)lump sum",
        "(?i)pension",
        "(?i)annuity",
        "(?i)early (access|release)",
        "(?i)preservation age"
    ]
    
    pattern := access_patterns[_]
    regex.match(pattern, text)
}

# Check if advice is retirement planning-related
is_retirement_planning_advice(text) if {
    planning_patterns := [
        "(?i)retirement (plan|planning|strategy)",
        "(?i)retirement income",
        "(?i)retirement lifestyle",
        "(?i)retirement budget",
        "(?i)retirement (goal|objective)"
    ]
    
    pattern := planning_patterns[_]
    regex.match(pattern, text)
}

# Check if advice is fund selection-related
is_fund_selection_advice(text) if {
    fund_patterns := [
        "(?i)(super|superannuation) fund",
        "(?i)SMSF",
        "(?i)self-managed",
        "(?i)industry fund",
        "(?i)retail fund",
        "(?i)fund (option|choice|selection)"
    ]
    
    pattern := fund_patterns[_]
    regex.match(pattern, text)
}

# Helper functions for best interest check

# Check if advice considers client goals
contains_client_goals_consideration(text) if {
    goal_patterns := [
        "(?i)your (goal|objective|aim)",
        "(?i)you (want|aim) to",
        "(?i)your retirement (need|goal|plan)",
        "(?i)based on your (situation|circumstances|needs)",
        "(?i)considering your (situation|circumstances|needs)"
    ]
    
    pattern := goal_patterns[_]
    regex.match(pattern, text)
}

# Check if advice includes risk assessment
contains_risk_assessment(text) if {
    risk_patterns := [
        "(?i)risk (profile|tolerance|appetite)",
        "(?i)(low|medium|high) risk",
        "(?i)comfort with risk",
        "(?i)risk and return",
        "(?i)risk (assessment|evaluation)"
    ]
    
    pattern := risk_patterns[_]
    regex.match(pattern, text)
}

# Check for prohibited advice
contains_prohibited_advice(text) if {
    prohibited_patterns := [
        "(?i)guarantee(d) (return|income|profit)",
        "(?i)promise(d) (return|income|profit)",
        "(?i)no risk",
        "(?i)can't lose",
        "(?i)certain (gain|profit)",
        "(?i)always (perform|beat|outperform)"
    ]
    
    pattern := prohibited_patterns[_]
    regex.match(pattern, text)
}

# Helper functions for advice scope checks

# Investment advice scope check
investment_advice_scope_check(text) if {
    # Investment advice should not be overly specific about security selection
    not regex.match("(?i)you should (buy|purchase|invest in|sell) (shares in |stock in )?[A-Z]{1,5}", text)
}

# Contribution advice scope check
contribution_advice_scope_check(text) if {
    # Contribution advice should mention tax considerations
    regex.match("(?i)tax (benefit|implication|outcome|consequence|consideration)", text)
}

# Benefit access scope check
benefit_access_scope_check(text) if {
    # Benefit access advice should mention preservation rules
    regex.match("(?i)preservation (age|rule|requirement)", text)
}

# Retirement planning scope check
retirement_planning_scope_check(text) if {
    # Retirement planning advice should be holistic
    regex.match("(?i)(lifestyle|expense|budget|income stream|longevity)", text)
}

# Fund selection scope check
fund_selection_scope_check(text) if {
    # Fund selection advice should mention comparison factors
    regex.match("(?i)(fee|performance|insurance|service|investment option)", text)
}

# General retirement advice scope check
general_retirement_advice_scope_check(text) if {
    # General advice should be educational in nature
    regex.match("(?i)(consider|option|alternative|strategy|approach)", text)
}

# Helper functions for disclosure checks

# Check for required disclosures
required_disclosure_check(text) if {
    # Basic required disclosures for retirement advice
    regex.match("(?i)(past performance|future performance|not a (guarantee|prediction))", text)
}

# Check for risk disclosures
risk_disclosure_check(text) if {
    # Risk-related disclosures
    regex.match("(?i)(risk|market fluctuation|potential loss|value may (fall|decline))", text)
}

# Check for fees and costs disclosures
fees_and_costs_disclosure_check(text) if {
    # Fee and cost disclosures when discussing investment options
    not is_investment_advice(text)
} else if {
    # For investment advice, must include fee disclosure
    regex.match("(?i)(fee|cost|expense|charge)", text)
}

# Helper functions for disclaimer checks

# Check for general disclaimers
general_disclaimer_check(text) if {
    # General retirement advice disclaimers
    regex.match("(?i)(general advice|not personal advice|not tailored|consider your personal (situation|circumstances))", text)
}

# Check for specific disclaimers based on advice type
specific_disclaimer_check(text) if {
    is_investment_advice(text)
    regex.match("(?i)(investment|market) (risk|fluctuation|volatility)", text)
} else if {
    is_fund_selection_advice(text)
    regex.match("(?i)(research|compare|consider) (multiple|different) (funds|options)", text)
} else if {
    # For other advice types, general disclaimer is sufficient
    true
}

# Check for professional advice referral
professional_advice_referral_check(text) if {
    # Advice should suggest consulting qualified professionals
    regex.match("(?i)(consult|speak|talk|discuss with) (a |your )?(financial (adviser|advisor|planner)|tax (adviser|advisor|accountant)|professional)", text)
}

# Jurisdiction-specific compliance functions

# Australia-specific compliance
jurisdiction_specific_compliance("Australia", text) if {
    # Check for ASIC compliance elements
    regex.match("(?i)(general advice warning|not taking into account your objectives|financial situation or needs)", text)
}

# US-specific compliance
jurisdiction_specific_compliance("US", text) if {
    # Check for US retirement-specific elements
    regex.match("(?i)(not (a substitute for|replacing) professional advice|tax consequences|consult (a |your )?tax (professional|advisor))", text)
}

# Default jurisdiction compliance (when not Australia or US)
jurisdiction_specific_compliance(jurisdiction, text) if {
    # Default compliance check for other jurisdictions
    professional_advice_referral_check(text)
}

# Rejection reasons
rejection_reasons = reasons if {
    reasons := array.concat(
        output_filtering_rejection_reasons,
        array.concat(
            document_type_reasons,
            array.concat(
                best_interest_reasons,
                array.concat(
                    advice_scope_reasons,
                    array.concat(
                        disclosure_reasons,
                        array.concat(
                            disclaimer_reasons,
                            regulatory_reasons
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

# Retirement advice output specific rejection reasons
retirement_advice_output_rejection_reasons = array.concat(
    document_type_reasons,
    array.concat(
        best_interest_reasons,
        array.concat(
            advice_scope_reasons,
            array.concat(
                disclosure_reasons,
                array.concat(
                    disclaimer_reasons,
                    regulatory_reasons
                )
            )
        )
    )
)

document_type_reasons = reasons if {
    not input.content_type == "output"
    reasons := [{"category": "Content Type", "reason": "Expected output document but received another type"}]
} else = [] if {
    true
}

best_interest_reasons = array.concat(
    client_goals_reasons,
    array.concat(risk_assessment_reasons, prohibited_advice_reasons)
)

client_goals_reasons = reasons if {
    not contains_client_goals_consideration(input.content)
    reasons := [{"category": "Best Interest", "reason": "Output does not demonstrate consideration of client goals or objectives"}]
} else = [] if {
    true
}

risk_assessment_reasons = reasons if {
    not contains_risk_assessment(input.content)
    reasons := [{"category": "Best Interest", "reason": "Output does not include appropriate risk assessment or discussion"}]
} else = [] if {
    true
}

prohibited_advice_reasons = reasons if {
    contains_prohibited_advice(input.content)
    reasons := [{"category": "Best Interest", "reason": "Output contains prohibited advice such as guarantees or promises of returns"}]
} else = [] if {
    true
}

advice_scope_reasons = reasons if {
    not advice_scope_check(input.content)
    reasons := [{"category": "Advice Scope", "reason": "Output exceeds appropriate scope for retirement advice"}]
} else = [] if {
    true
}

disclosure_reasons = array.concat(
    required_disclosure_reasons,
    array.concat(risk_disclosure_reasons, fees_disclosure_reasons)
)

required_disclosure_reasons = reasons if {
    not required_disclosure_check(input.content)
    reasons := [{"category": "Disclosure", "reason": "Output is missing required disclosures about past and future performance"}]
} else = [] if {
    true
}

risk_disclosure_reasons = reasons if {
    not risk_disclosure_check(input.content)
    reasons := [{"category": "Disclosure", "reason": "Output is missing required risk disclosures"}]
} else = [] if {
    true
}

fees_disclosure_reasons = reasons if {
    is_investment_advice(input.content)
    not fees_and_costs_disclosure_check(input.content)
    reasons := [{"category": "Disclosure", "reason": "Output is missing required fee and cost disclosures"}]
} else = [] if {
    true
}

disclaimer_reasons = array.concat(
    general_disclaimer_reasons,
    array.concat(
        specific_disclaimer_reasons,
        professional_advice_reasons
    )
)

general_disclaimer_reasons = reasons if {
    not general_disclaimer_check(input.content)
    reasons := [{"category": "Disclaimer", "reason": "Output is missing general advice disclaimers"}]
} else = [] if {
    true
}

specific_disclaimer_reasons = reasons if {
    not specific_disclaimer_check(input.content)
    reasons := [{"category": "Disclaimer", "reason": "Output is missing specific disclaimers relevant to the advice type"}]
} else = [] if {
    true
}

professional_advice_reasons = reasons if {
    not professional_advice_referral_check(input.content)
    reasons := [{"category": "Disclaimer", "reason": "Output does not include reference to seeking professional advice"}]
} else = [] if {
    true
}

regulatory_reasons = reasons if {
    not regulatory_compliance_check
    reasons := [{"category": "Regulatory Compliance", "reason": "Output does not comply with jurisdiction-specific regulations"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Retirement Advice Output Guardrail",
    "description": "Output validation guardrail for retirement advice in GenAI applications",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "APRA CPS 230",
        "ASIC RG 255",
        "ERISA",
        "DOL Fiduciary Rule"
    ]
}