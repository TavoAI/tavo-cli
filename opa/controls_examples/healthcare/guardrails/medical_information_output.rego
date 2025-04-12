package tavoai.healthcare.guardrails.medical_information_output

# Runtime guardrail for medical information output validation
# Based on EU AI Act, NIST AI RMF, and APRA CPS 230
# Specific to healthcare industry

# Import common modules
import data.tavoai.common.output_filtering
import data.tavoai.common.data.patterns

# Default deny
default allow = false

# Allow medical information output if all checks pass
allow if {
    # Basic output validation checks
    output_filtering.allow
    
    # Verify this is an output document
    input.content_type == "output"
    
    # Healthcare-specific output checks
    medical_output_checks
}

# Core medical information output checks
medical_output_checks if {
    # Check if the output contains appropriate medical disclaimers
    contains_medical_disclaimers(input.content)
    
    # Check if the output mentions limitations
    contains_limitations(input.content)
    
    # Check if the output avoids medical misinformation
    not contains_medical_misinformation(input.content)
    
    # Check for jurisdiction compliance
    jurisdiction_compliance
}

# Helper function to check for medical disclaimers
contains_medical_disclaimers(text) if {
    disclaimer_patterns := [
        "(?i)not (a )?(medical|healthcare|clinical) advice",
        "(?i)consult.{1,30}(healthcare|medical) (professional|provider|doctor)",
        "(?i)not.{1,30}substitute.{1,30}(medical|healthcare|professional).{1,30}(advice|consultation|opinion)",
        "(?i)speak.{1,30}(with|to).{1,30}(healthcare|medical) (professional|provider|doctor)"
    ]
    
    pattern := disclaimer_patterns[_]
    regex.match(pattern, text)
}

# Helper function to check for limitations
contains_limitations(text) if {
    limitations_patterns := [
        "(?i)(information|content).{1,30}(general|educational).{1,30}(purposes|use)",
        "(?i)(cannot|not able to).{1,30}(diagnose|treat|prescribe)",
        "(?i)based.{1,30}(general|available).{1,30}information",
        "(?i)individual.{1,30}(conditions|situations|cases).{1,30}(may|might|can).{1,30}(vary|differ|be different)"
    ]
    
    pattern := limitations_patterns[_]
    regex.match(pattern, text)
}

# Helper function to check for medical misinformation
contains_medical_misinformation(text) if {
    misinformation_patterns := [
        "(?i)(cure|treat|heal).{1,30}(cancer|diabetes|alzheimer|hiv|aids).{1,30}(with|using|through).{1,30}(natural|alternative|home)",
        "(?i)vaccines.{1,30}(cause|linked to).{1,30}autism",
        "(?i)(covid|coronavirus).{1,30}(hoax|fake|conspiracy)",
        "(?i)5g.{1,30}(cause|spread).{1,30}(covid|coronavirus|virus|disease)"
    ]
    
    pattern := misinformation_patterns[_]
    regex.match(pattern, text)
}

# Jurisdiction compliance check
jurisdiction_compliance if {
    # Get jurisdiction from metadata
    jurisdiction := input.metadata.jurisdiction
    
    # Apply jurisdiction-specific rules
    jurisdiction_specific_compliance(jurisdiction, input.content)
}

# US-specific compliance
jurisdiction_specific_compliance("US", text) if {
    # FDA compliance - must include specific medical device disclaimers if applicable
    not contains_medical_device_references(text)
} else if {
    # If there are medical device references, must include FDA disclaimer
    contains_medical_device_references(text)
    contains_fda_disclaimer(text)
}

# EU-specific compliance
jurisdiction_specific_compliance("EU", text) if {
    # GDPR and EU medical information compliance
    not contains_treatment_recommendations(text)
} else if {
    # If there are treatment recommendations, must include EU healthcare disclaimer
    contains_treatment_recommendations(text)
    contains_eu_healthcare_disclaimer(text)
}

# Australia-specific compliance
jurisdiction_specific_compliance("Australia", text) if {
    # TGA compliance
    not contains_therapeutic_claims(text)
} else if {
    # If there are therapeutic claims, must include TGA disclaimer
    contains_therapeutic_claims(text)
    contains_tga_disclaimer(text)
}

# Default jurisdiction compliance (when not US, EU, or Australia)
jurisdiction_specific_compliance(jurisdiction, text) if {
    # Default compliance check for other jurisdictions
    true
}

# Helper functions for jurisdiction-specific compliance

# Check for medical device references
contains_medical_device_references(text) if {
    medical_device_patterns := [
        "(?i)medical device",
        "(?i)(monitor|track).{1,30}(blood pressure|glucose|heart rate)",
        "(?i)(wearable|implant).{1,30}(device|monitor|tracker)"
    ]
    
    pattern := medical_device_patterns[_]
    regex.match(pattern, text)
}

# Check for FDA disclaimer
contains_fda_disclaimer(text) if {
    regex.match("(?i)(FDA|Food and Drug Administration).{1,50}(not|hasn't).{1,50}(approved|evaluated|cleared)", text)
}

# Check for treatment recommendations
contains_treatment_recommendations(text) if {
    treatment_patterns := [
        "(?i)(recommend|suggest|advise).{1,30}(taking|using|try).{1,30}(medication|drug|treatment)",
        "(?i)(start|begin|initiate).{1,30}(therapy|treatment|medication)",
        "(?i)(increase|decrease|adjust).{1,30}(dose|dosage|medication)"
    ]
    
    pattern := treatment_patterns[_]
    regex.match(pattern, text)
}

# Check for EU healthcare disclaimer
contains_eu_healthcare_disclaimer(text) if {
    regex.match("(?i)(information|content).{1,50}(complies|accordance|aligned).{1,50}(EU|European Union).{1,50}(regulations|directives|guidelines)", text)
}

# Check for therapeutic claims
contains_therapeutic_claims(text) if {
    therapeutic_patterns := [
        "(?i)(treats|cures|alleviates|prevents).{1,30}(disease|condition|disorder)",
        "(?i)(therapeutic|medicinal|healing).{1,30}(benefits|properties|effects)",
        "(?i)clinically.{1,30}(proven|tested|shown)"
    ]
    
    pattern := therapeutic_patterns[_]
    regex.match(pattern, text)
}

# Check for TGA disclaimer
contains_tga_disclaimer(text) if {
    regex.match("(?i)(TGA|Therapeutic Goods Administration).{1,50}(not|hasn't).{1,50}(approved|evaluated)", text)
}

# Rejection reasons
rejection_reasons = reasons if {
    reasons := array.concat(
        output_filtering_rejection_reasons,
        array.concat(
            document_type_reasons,
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
}

# Output filtering rejection reasons
output_filtering_rejection_reasons = reasons if {
    not output_filtering.allow
    reasons := output_filtering.rejection_reasons
} else = [] if {
    true
}

# Medical output specific rejection reasons
document_type_reasons = reasons if {
    not input.content_type == "output"
    reasons := [{"category": "Content Type", "reason": "Expected output document but received another type"}]
} else = [] if {
    true
}

disclaimer_reasons = reasons if {
    not contains_medical_disclaimers(input.content)
    reasons := [{"category": "Medical Disclaimers", "reason": "Output is missing required medical disclaimers"}]
} else = [] if {
    true
}

limitation_reasons = reasons if {
    not contains_limitations(input.content)
    reasons := [{"category": "Limitations", "reason": "Output does not mention limitations of the provided information"}]
} else = [] if {
    true
}

misinformation_reasons = reasons if {
    contains_medical_misinformation(input.content)
    reasons := [{"category": "Misinformation", "reason": "Output contains potential medical misinformation"}]
} else = [] if {
    true
}

jurisdiction_reasons = reasons if {
    not jurisdiction_compliance
    reasons := [{"category": "Jurisdiction Compliance", "reason": "Output does not comply with jurisdiction-specific healthcare regulations"}]
} else = [] if {
    true
}

# Policy Metadata
policy_metadata = {
    "name": "Medical Information Output Guardrail",
    "description": "Output validation guardrail for medical information in GenAI applications",
    "version": "1.1.0",
    "last_updated": "2023-07-15",
    "regulatory_references": [
        "EU AI Act",
        "NIST AI RMF",
        "APRA CPS 230",
        "FDA Regulations",
        "HIPAA",
        "EU MDR",
        "TGA Requirements"
    ]
} 