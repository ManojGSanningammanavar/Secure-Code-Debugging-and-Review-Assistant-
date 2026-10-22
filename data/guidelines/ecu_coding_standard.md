# ECU Embedded C Coding Standard (internal, v2.1)

This internal standard summarises how our ECU software teams apply MISRA C:2012 and CERT C.
It paraphrases intent only; the licensed MISRA document remains the normative source.

## ECU-CS-01 Scope and deviations
Applies to all production C code that runs on electronic control units. A deviation from a required
rule needs a written deviation record approved by the software quality lead. Advisory rules may be
deviated with a code comment that references the deviation ID. Generated code is reviewed against the
generator's qualification report instead of line by line.

## ECU-CS-02 Structured control flow (MISRA 15.1, 15.5, 15.6, 16.4, 17.2, 13.4)
Control flow must be easy to verify. Do not use goto (Rule 15.1, advisory). Prefer a single point of exit
at the end of a function (Rule 15.5, advisory). Every if, else, for and while body must be a compound
statement in braces, because brace-less bodies hide bugs when lines are added later (Rule 15.6).
Every switch must have a default clause that handles unexpected values, normally by reporting an error
and entering a safe state (Rule 16.4). Functions must not call themselves directly or indirectly because
stack usage then cannot be bounded (Rule 17.2). Do not use the result of an assignment inside a condition;
writing `if (x = 5)` is almost always a typo for `==` (Rule 13.4).

## ECU-CS-03 Pointer validity and NULL handling (Dir 4.1, CWE-476)
Run-time failures must be minimised. Every pointer received from outside the module (API parameters,
look-up functions, allocation) must be validated against NULL before it is dereferenced, unless the
interface contract documented in the header guarantees non-NULL and a static analysis proof exists.
Functions that can return NULL must document it, and callers must check the result. On failure return
E_NOT_OK and report the error through the Default Error Tracer (Det_Report).

## ECU-CS-04 Buffer and array bounds (Rule 18.1, 21.17, 21.18, CWE-120/787/129/193)
All buffer writes must be bounded by the destination size. Unbounded functions such as strcpy, strcat,
sprintf and gets are forbidden. Copy lengths that come from callers or from the network (CAN, UDS, LIN)
must be checked against sizeof(destination) before memcpy. Array indices that come from parameters must
be checked against the array dimension. Loop bounds that equal the array length must use `<` rather
than `<=`; the classic off-by-one writes one element past the end and corrupts adjacent RAM.

## ECU-CS-05 Memory and resource management (Rule 21.3, 22.1, CWE-401)
Dynamic heap allocation (malloc, calloc, realloc, free) is not permitted in ECU production code because
fragmentation and allocation failure are non-deterministic (Rule 21.3). Use statically sized buffers
or a qualified fixed-block memory pool. Where an exception is approved, every acquired resource must be
released on every path, including early error returns (Rule 22.1). Prefer a single cleanup block at the
end of the function.

## ECU-CS-06 Initialisation (Rule 9.1, CWE-457)
The value of an automatic variable must not be read before it has been set. Initialise local variables
at their declaration, especially accumulators, status flags and return codes. A variable assigned only
inside an if branch or a switch case is "maybe uninitialised" on other paths and must be initialised
at declaration.

## ECU-CS-07 Interrupts and shared data (Dir 5.1, CWE-362/662)
Data shared between an interrupt service routine and task-level code must be declared volatile so the
compiler re-reads it on every access. Volatile does not make access atomic: any read-modify-write of
shared data from task level, and any access to data wider than the CPU's native word, must be done inside
a critical section (for example SchM_Enter/SchM_Exit or disabling interrupts for the shortest possible time).

## ECU-CS-08 Arithmetic safety (Rule 10.3, 12.4, Dir 4.1, CWE-190/197/369)
Do not assign the result of an arithmetic expression to a narrower essential type without an explicit,
range-checked conversion (Rule 10.3). Compute in a wider type, saturate to the target range, then cast.
Multiplications that compute allocation or buffer sizes must be checked for overflow first. Every division
or modulo by a variable must be guarded by an explicit non-zero check with a documented fallback value;
sensor counts and time deltas are frequently zero at start-up.

## ECU-CS-09 Library and API usage (Rule 17.7, 21.6, 21.7, CWE-252)
The return value of every non-void function must be used; if it is intentionally ignored, cast the call
to (void) and add a comment explaining why (Rule 17.7). Standard input/output functions from stdio.h
are not used in ECU software; use the diagnostic logging service (Rule 21.6). atoi, atol, atoll and atof
are forbidden because they have undefined behaviour on overflow and give no error indication; use strtol
or strtoul with end-pointer and range checks (Rule 21.7).

## ECU-CS-10 Complexity and AI-assisted findings
Functions should keep cyclomatic complexity at or below 15 and nesting depth at or below 4. Hotspots flagged
by the complexity model should be considered for refactoring and need focused unit tests. Findings produced
only by a machine-learning model are hypotheses: a reviewer must confirm them against the code before they
are accepted, and confirmed or rejected decisions are fed back to improve the triage model.
