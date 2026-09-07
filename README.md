# OPA Utilities package

## Framework-scoped result views

`exceptions.FilterExceptionsByFrameworks` filters posture exceptions with the
same case-insensitive and anchored-regexp matching rules used by the exception
processor. Returned exceptions are copies whose `PosturePolicies` contain only
the matching `(framework, control, rule)` tuples, so callers can derive an
effective framework status without mutating the shared evaluation result. An
empty framework-name slice selects framework-agnostic policies.

Result and summary `GetStatus` methods carry the effective substatus through
rule, control, resource, framework, and top-level views. Summary substatuses
are derived from serialized control status information, so this does not add a
new report field.
