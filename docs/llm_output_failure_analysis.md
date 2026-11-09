# LLM Output Failure Analysis

## Purpose

This document records failures observed while evaluating the rule-based baseline,
standalone LLM, and retrieval-augmented LLM for cloud-security investigations.

These findings are from controlled research experiments, not real AWS attacks.

## 1. Initial structured-output failures

During the initial six-case CloudTrail development comparison:

- LLM-only: 5 of 6 investigations failed.
- RAG-assisted: 6 of 6 investigations failed.
- Most failures were JSONDecodeError exceptions involving incomplete strings
  or invalid JSON structure.

These failures prevented reliable evaluation even when the model produced text.

## 2. Citation and model-service failures

A subsequent comparison identified:

- Model-generated knowledge citations that were not provided to the LLM.
- Validation correctly rejected these unsupported citations.
- One HTTP 500 error from the local model service.
- The RAG method completed all six cases in that run, while LLM-only failed.

This exposed the need for strict output validation, retries, and explicit
failure reporting.

## 3. Corrected comparison

After further output-handling improvements, both AI methods completed
the six-case CloudTrail development comparison.

However, valid structured output did not guarantee correct classification
or evidence-grounded explanations.

## 4. Final Wazuh-linked experiment

The final controlled experiment used 100 synthetic cases and 400 verified
Wazuh event records.

Classification accuracy:

| Method | Accuracy |
|---|---:|
| Rule-based baseline | 100% |
| LLM-only | 53% |
| RAG-assisted LLM | 30% |

The RAG model frequently returned suspicious classifications without
adequately distinguishing benign and designated-critical scenarios.

The rule-based baseline benefited from conditions closely aligned with
the deliberately constructed synthetic scenarios.

## 5. Hallucination examples

Observed model explanations included:

- Confusing CloudTrail DeleteTrail with deletion of an S3 bucket.
- Interpreting repeated failed logins as benign.
- Claiming brute-force activity without sufficient supporting evidence.
- Presenting unsupported conclusions about API operation outcomes.

These findings demonstrate why valid JSON and valid evidence identifiers
do not necessarily establish factual accuracy.

## 6. Implemented safeguards

The completed prototype includes:

- Wazuh-to-source event identity verification.
- Strict structured-response and citation validation.
- Explicit recording of model errors and abstentions.
- Conservative automated checks for selected unsupported claims.
- Rule-enforced investigation priority and human-review requirements.
- Executive reports that separate observed evidence from raw AI claims.

## 7. Research conclusion

A small pretrained local language model did not outperform conventional
rules in this controlled experiment. Adding retrieved security context
did not automatically improve classification performance.

The resulting system is a functioning human-supervised research prototype,
not a production-ready autonomous incident-response service.

These limitations are retained as part of the research findings.

See also:
- experiment_log.md
- wazuh_ai_final_results.md
- RESEARCH_JOURNEY_AND_LIMITATIONS.md
