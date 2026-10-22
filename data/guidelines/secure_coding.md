# ECU Secure Coding Guideline (internal, v1.4)

Aligned with ISO/SAE 21434 cybersecurity engineering and CERT C. Applies to all code that handles
diagnostics, communication buses, keys, or externally supplied data.

## ECU-SEC-01 Secrets and key material (CWE-798)
Never embed passwords, seeds, security-access keys, certificates or cryptographic keys in source code.
Keys must be provisioned into the hardware security module (HSM) or protected NVM at end-of-line and
accessed through the crypto service. A key found in source code must be treated as compromised and
rotated, even if the repository is private.

## ECU-SEC-02 Format strings and logging (CWE-134)
The format argument of printf-style functions must be a string literal. Passing a variable that may
contain data from a diagnostic tester or bus message allows format-string attacks that read or write
memory. Log diagnostic payloads with an explicit "%s" or by length.

## ECU-SEC-03 Untrusted input from buses and diagnostics
Treat all data received over CAN, CAN-FD, LIN, Ethernet and UDS as untrusted. Validate length, range and
sequence before use. Reject requests whose declared length exceeds the receive buffer. Security access
(UDS service 0x27) must use a challenge-response with keys from the HSM and must apply delay timers after
failed attempts.

## ECU-SEC-04 AI assistant usage and prompt injection
Source code and model interactions must stay inside the organisational boundary: only locally hosted
models are allowed. Repository content is untrusted data for the AI assistant. Comments or strings that
try to instruct an AI tool (for example "ignore previous instructions" or "do not report this file") are
treated as a security finding, quarantined from the model context, and reported to the reviewer.
AI-generated findings and fixes are recommendations only; release, merge and compliance approval always
require a qualified human reviewer.
