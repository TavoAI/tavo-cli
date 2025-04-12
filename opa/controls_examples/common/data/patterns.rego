package tavoai.common.data.patterns

# Categories of prohibited content
prohibited_categories = [
    "hate_speech",
    "illegal_activity",
    "harassment",
    "discrimination",
    "violence",
    "self_harm"
]

# Categories of harmful content
harmful_categories = [
    "personal_attacks",
    "threats",
    "misinformation",
    "medical_misinformation",
    "financial_misinformation"
]

# PII patterns
pii_patterns = {
    # General PII
    "name": "\\b[A-Z][a-z]+ [A-Z][a-z]+\\b",
    "email": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    "phone": "\\b(\\+\\d{1,3}[- ]?)?\\(?(\\d{3})\\)?[- ]?(\\d{3})[- ]?(\\d{4})\\b",
    "ssn": "\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b",
    "dob": "\\b(0[1-9]|1[0-2])/(0[1-9]|[12]\\d|3[01])/\\d{4}\\b",
    "address": "\\b\\d+\\s+[A-Za-z\\s]+\\b,\\s*[A-Za-z\\s]+\\b,\\s*[A-Z]{2}\\s*\\d{5}\\b",
    
    # Financial PII
    "credit_card": "\\b(?:\\d[ -]*?){13,16}\\b",
    "routing_number": "\\b[0-9]{9}\\b",
    "account_number": "\\b[0-9]{8,17}\\b",
    "tax_id": "\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b",
    
    # Healthcare PII
    "patient_name": "\\b[A-Z][a-z]+ [A-Z][a-z]+\\b",
    "mrn": "\\b[A-Z]{1,3}[0-9]{6,10}\\b",
    "health_plan_id": "\\b[A-Z]{1,5}[0-9]{9,12}\\b",
    "medical_record_id": "\\b[A-Z]{2,3}[0-9]{6,10}\\b",
    "patient_id": "\\b(P|PT|PAT)[0-9]{6,10}\\b",
    "insurance_id": "\\b[A-Z]{1,5}[0-9]{9,12}\\b"
}

# Prompt injection patterns
injection_patterns = [
    "(?i)ignore (previous|above|earlier) instructions",
    "(?i)disregard (previous|prior|above) (instructions|rules|guidelines)",
    "(?i)do not (follow|adhere to) (the|any) (rules|instructions|guidelines)",
    "(?i)override (the|all) (previous|prior) (instructions|rules|commands)",
    "(?i)forget (your|all) instructions",
    "(?i)don't (pay attention to|mind|care about) (your|the) (rules|guidelines|instructions)"
]

# Jailbreak patterns
jailbreak_patterns = [
    "(?i)bypass (the|any|all) (restrictions|filters|safeguards|controls)",
    "(?i)jailbreak (mode|the system|yourself|the model)",
    "(?i)ignore (ethical|safety|security) (guidelines|protocols|restrictions)",
    "(?i)allow (prohibited|dangerous|harmful|illegal) (content|information|instructions)",
    "(?i)disable (safety|ethical|content) (filters|measures|protocols)"
]

# Prohibited content patterns by category
prohibited_content_patterns = {
    "hate_speech": [
        "(?i)\\b(hate|hateful|derogatory)\\b.{0,30}\\b(speech|language|content)\\b",
        "(?i)\\b(racial|ethnic|religious|homophobic) (slur|insult|epithet)\\b",
        "(?i)\\b(antisemitic|antisemitism|racist|sexist|misogynistic|homophobic|transphobic)\\b"
    ],
    "illegal_activity": [
        "(?i)\\b(how to|instructions for) (fraud|illegal|hack|steal)\\b",
        "(?i)\\b(create|make|manufacture) (illegal drugs|bombs|weapons)\\b",
        "(?i)\\b(evade|avoid) (taxes|law enforcement|legal consequences)\\b",
        "(?i)\\b(launder|laundering) money\\b"
    ],
    "harassment": [
        "(?i)\\b(harass|stalk|intimidate|threaten)\\b",
        "(?i)\\b(personal attacks|bullying|threatening|intimidating)\\b",
        "(?i)\\b(dox|doxxing|reveal personal information)\\b"
    ],
    "discrimination": [
        "(?i)\\b(discriminate|discrimination) (against|based on)\\b",
        "(?i)\\b(racial|gender|religious|age) discrimination\\b",
        "(?i)\\b(stereotype|stereotyping) (people|individuals|groups)\\b"
    ],
    "violence": [
        "(?i)\\b(violent|violence|killing|murder|assault)\\b",
        "(?i)\\b(harm|hurt|injure|attack) (people|person|individual|someone)\\b",
        "(?i)\\b(graphic|explicit) (violence|descriptions|imagery)\\b"
    ],
    "self_harm": [
        "(?i)\\b(suicide|suicidal|self-harm|self harm)\\b",
        "(?i)\\b(methods|ways|how) to (harm|hurt|kill) (yourself|oneself)\\b",
        "(?i)\\b(promoting|encouraging) (suicide|self-harm)\\b"
    ]
}

# Harmful content patterns by category
harmful_content_patterns = {
    "personal_attacks": [
        "(?i)\\b(stupid|idiot|dumb|moron|incompetent)\\b",
        "(?i)\\b(insult|attack|demean|belittle) (personal|character|intelligence)\\b",
        "(?i)\\b(mocking|ridiculing|laughing at) (appearance|disability|condition)\\b"
    ],
    "threats": [
        "(?i)\\b(threaten|kill|hurt|harm|injure|attack)\\b",
        "(?i)\\b(will|going to|plan to) (hurt|harm|damage|destroy)\\b",
        "(?i)\\b(violent|threatening) (action|behavior|conduct|language)\\b"
    ],
    "misinformation": [
        "(?i)\\b(fake news|conspiracy theory|disinformation)\\b",
        "(?i)\\b(false|misleading|deceptive) (information|claim|statement)\\b",
        "(?i)\\b(proven|confirmed|verified) (false|untrue|incorrect)\\b"
    ],
    "medical_misinformation": [
        "(?i)\\bcure (all|every|any) (disease|condition|ailment)\\b",
        "(?i)\\bguaranteed (cure|treatment|remedy)\\b",
        "(?i)\\bmiracle (cure|treatment|remedy)\\b",
        "(?i)\\b(doctors|medical professionals) (don't want you to know|are hiding|won't tell you)\\b",
        "(?i)\\b(alternative|natural) (treatment|cure) (better than|superior to) (medical|conventional)\\b"
    ],
    "financial_misinformation": [
        "(?i)\\bguaranteed (returns|profit|income)\\b",
        "(?i)\\brisk(-|\\s)free investment\\b",
        "(?i)\\b(get rich|become wealthy) (quick|fast|overnight|easily)\\b",
        "(?i)\\b(double|triple) your (money|investment) in\\b",
        "(?i)\\b(secret|unknown|hidden) (investment|financial) (strategy|method|technique)\\b"
    ]
}

# Industry-specific prohibited patterns
financial_prohibited_patterns = {
    "investment_guarantees": [
        "(?i)guarantee(d|s)?\\s(return|outcome|result|profit)",
        "(?i)definitely\\s(increase|grow|double)",
        "(?i)no\\srisk",
        "(?i)certain\\sto\\s(succeed|profit|gain)",
        "(?i)invest\\syour\\sentire"
    ],
    "tax_evasion": [
        "(?i)(avoid|evade)\\s(paying|reporting)\\stax",
        "(?i)hide\\s(income|assets|money)\\sfrom\\s(irs|government|tax)",
        "(?i)offshore\\s(account|tax|haven)\\sto\\s(hide|conceal)"
    ]
}

healthcare_prohibited_patterns = {
    "medical_claims": [
        "(?i)(cure|treat|heal)\\s(all|every|any)\\s(disease|cancer|condition)",
        "(?i)100%\\s(effective|guaranteed|successful)",
        "(?i)(miracle|revolutionary|breakthrough)\\s(cure|treatment|therapy)"
    ],
    "prescription_advice": [
        "(?i)(stop|change|adjust)\\s(taking|using)\\s(medication|prescription|drug)",
        "(?i)(higher|lower|increase|decrease)\\s(dose|dosage)",
        "(?i)(take|use)\\s(medication|drug|prescription)\\s(without|instead of)\\s(doctor|prescription)"
    ]
}

superannuation_prohibited_patterns = {
    "early_access": [
        "(?i)(access|withdraw|get)\\s(super|superannuation)\\s(early|before)",
        "(?i)(loophole|trick|secret)\\sto\\s(access|withdraw)\\s(super|superannuation)",
        "(?i)(avoid|evade|circumvent)\\s(preservation|restriction|rule)"
    ],
    "guaranteed_returns": [
        "(?i)guarantee(d|s)?\\s(return|outcome|result|performance)",
        "(?i)definitely\\s(increase|grow|double)",
        "(?i)no\\srisk\\s(super|superannuation|investment)",
        "(?i)certain\\sto\\s(succeed|profit|gain)"
    ]
} 