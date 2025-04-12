# Input and Output Samples for TavoAI Guardrails

This directory contains sample input and output JSON files for testing and using the TavoAI guardrail policies. These samples demonstrate the separated input/output structure that leverages centralized pattern definitions and improves validation workflow.

## Separated Input/Output Approach

Our guardrails now use a separated input/output approach:

1. 🔄 **Two-Stage Validation**: Validate input queries first, then validate output responses separately
2. 🏷️ **Explicit Type Identification**: Each JSON document clearly identifies as either "input" or "output"
3. 🔗 **Request Linking**: Input and output are linked by a shared request_id
4. 🛡️ **Specialized Rules**: Different validation rules for input vs. output

## Centralized Pattern Approach

Pattern definitions are centralized in `common/data/patterns.rego`. This means:

1. 🎯 **Simplified JSON Structure**: Your JSON is much cleaner and focused only on the data and configuration settings
2. 🔄 **Consistent Pattern Enforcement**: All policies use the same vetted patterns for security, compliance, and safety
3. 🛠️ **Easier Maintenance**: Pattern updates and additions only need to be made in one place

## Input JSON Structure

```json
{
  "json_type": "input",
  "input": {
    "query": "User's input query to the AI system"
  },
  "metadata": {
    "model": {
      "name": "GPT-4o",
      "version": "1.0",
      "provider": "OpenAI"
    },
    "jurisdiction": "US",
    "timestamp": "2023-07-15T12:00:00Z",
    "user": {
      "id": "user123",
      "type": "authenticated",
      "access_level": "standard"
    },
    "industry": "financial",
    "use_case": "customer_support"
  },
  "config": {
    "pii_detection_enabled": true,
    "pii_allowed_with_consent": false,
    "misinformation_detection_enabled": true,
    "bias_detection_enabled": true
  },
  "request_id": "req-12345-abcde"
}
```

## Output JSON Structure

```json
{
  "json_type": "output",
  "output": {
    "content": "AI-generated response that will be evaluated against guardrails"
  },
  "metadata": {
    "model": {
      "name": "GPT-4o",
      "version": "1.0",
      "provider": "OpenAI"
    },
    "jurisdiction": "US",
    "timestamp": "2023-07-15T12:00:05Z",
    "user": {
      "id": "user123",
      "type": "authenticated",
      "access_level": "standard"
    },
    "industry": "financial",
    "use_case": "customer_support"
  },
  "config": {
    "pii_detection_enabled": true,
    "pii_allowed_with_consent": false,
    "misinformation_detection_enabled": true,
    "bias_detection_enabled": true
  },
  "request_id": "req-12345-abcde"
}
```

## Templates

Two template options are provided for both input and output:

- `sample_template_input.json` and `sample_template_output.json`: Clean JSON templates with minimal metadata
- `sample_template_input.jsonc` and `sample_template_output.jsonc`: Templates with detailed comments explaining each field (requires JSONC support)

## Industry-Specific Samples

Sample input and output files for different industries:

### Financial Industry

- `financial/inputs/financial_advice_input.json` and `financial/inputs/financial_advice_output.json`: Samples for financial advice guardrail
- `financial/inputs/financial_data_protection_input.json` and `financial/inputs/financial_data_protection_output.json`: Samples for financial data protection guardrail

### Healthcare Industry

- `healthcare/inputs/medical_information_input.json` and `healthcare/inputs/medical_information_output.json`: Samples for medical information guardrail
- `healthcare/inputs/patient_data_protection_input.json` and `healthcare/inputs/patient_data_protection_output.json`: Samples for patient data protection guardrail

### Insurance Industry

- `insurance/inputs/insurance_claim_advice_input.json` and `insurance/inputs/insurance_claim_advice_output.json`: Samples for insurance claim advice guardrail

### Superannuation Industry

- `superannuation/inputs/retirement_advice_input.json` and `superannuation/inputs/retirement_advice_output.json`: Samples for retirement advice guardrail

## Minimum Required Configuration

You only need to provide minimal config flags to control policy behavior:

```json
"config": {
  "pii_detection_enabled": true,
  "pii_allowed_with_consent": false,
  "misinformation_detection_enabled": true,
  "bias_detection_enabled": true
}
```

## Testing with OPA

To evaluate input validation:

```bash
opa eval -i financial/inputs/financial_advice_input.json -d . "data.tavoai.financial.guardrails.financial_advice_input.allow_financial_advice_input"
```

To evaluate output validation:

```bash
opa eval -i financial/inputs/financial_advice_output.json -d . "data.tavoai.financial.guardrails.financial_advice_output.allow_financial_advice_output"
```

To get detailed rejection reasons:

```bash
# For input rejection reasons
opa eval -i financial/inputs/financial_advice_input.json -d . "data.tavoai.financial.guardrails.financial_advice_input.rejection_reasons"

# For output rejection reasons
opa eval -i financial/inputs/financial_advice_output.json -d . "data.tavoai.financial.guardrails.financial_advice_output.rejection_reasons"
``` 