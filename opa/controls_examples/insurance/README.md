# Insurance Industry Guardrails

This directory contains guardrail policies specifically designed for Generative AI and Agentic AI applications operating in the insurance industry. These policies help ensure compliance with insurance regulations and protect against common risks in insurance-related AI applications.

## Available Guardrails

### Insurance Claim Advice Guardrail
- **File**: [`guardrails/insurance_claim_advice.rego`](./guardrails/insurance_claim_advice.rego)
- **Purpose**: Ensures that AI-generated advice about insurance claims is factually accurate, properly qualified, contains appropriate disclaimers, and complies with insurance regulations.
- **Key Features**:
  - Prevents promises or guarantees about claim settlements
  - Requires appropriate disclaimers and limitations
  - Ensures compliance with jurisdiction-specific insurance regulations
  - Detects common insurance misinformation
  - Validates that advice recommends policy review

## Sample Inputs

Sample input files are provided to test each guardrail:

- [Insurance Claim Advice Sample](./inputs/insurance_claim_advice_sample.json): Example input for testing the insurance claim advice guardrail.

## Usage

To evaluate a policy against sample input:

```bash
opa eval -i insurance/inputs/insurance_claim_advice_sample.json -d . "data.tavoai.insurance.guardrails.insurance_claim_advice.allow_insurance_claim_advice"
```

To get detailed rejection reasons:

```bash
opa eval -i insurance/inputs/insurance_claim_advice_sample.json -d . "data.tavoai.insurance.guardrails.insurance_claim_advice.rejection_reasons"
```

## Regulatory Compliance

The insurance guardrails help ensure compliance with:

- Insurance-specific regulations (NAIC model acts, IDD, etc.)
- General AI regulations (EU AI Act, NIST AI RMF)
- Privacy regulations (GDPR, CCPA) for handling policyholder data

## Integration

These guardrails can be integrated into AI applications dealing with:

- Insurance claim handling and advice
- Policy recommendations and explanations
- Underwriting assistance
- Customer service in insurance contexts

For more information on integration, see the [main documentation](../README.md). 