# Validation Method and Evidence Limits

## Scope and recorded outcome

The September 19, 2026 exercise covered three unique ATT&CK techniques on
`win-target-01`. The operation chain contains five entries because Registry
Run Key and LSASS abilities were repeated; those repeats are not extra
technique coverage.

| Technique | Published evidence | Recorded outcome |
|---|---|---|
| T1547.001: Registry Run Keys | Sysmon 13 with a Run key value; Caldera completion entries | DETECTED |
| T1003.001: LSASS Memory | Failed Caldera ability, Defender detection/remediation record, Sysmon 10 from Defender | PREVENTED |
| T1070.004: File Deletion | Sysmon 26 with the seeded file path; successful Caldera entry | DETECTED |

See the [exercise investigation](detection-validation-001.md),
[published operation excerpts](../reports/operations/sapphros-detection-validation-v1.json),
[scenario](../scenarios/sapphros-detection-validation-v1.yml), and
[Sigma rules](../detections/sigma/).

## How I review a run

1. Identify the target, operation, technique, completion time, and execution
   status from Caldera.
2. Review the relevant Sysmon event IDs and fields around that time. Correlate
   target paths and source processes with the intended activity.
3. Check Defender records when an ability fails or expected attacker telemetry
   is absent. An execution failure alone does not establish prevention.
4. Compare the observed event fields with the Sigma selection and filter logic.
   Inspect benign activity that could satisfy the same selection.
5. Record the outcome, supporting evidence, tuning decisions, and remaining
   uncertainties in the exercise write-up.

## Meaning of the outcomes

- **DETECTED:** the documented lab review found telemetry consistent with the
  technique and the corresponding rule logic. This is manual validation;
  the repository does not include a SIEM alert export or an automated Sigma
  execution log demonstrating an end-to-end alert.
- **PREVENTED:** the lab investigation found evidence that Defender blocked the
  LSASS attempt. It does not prove successful credential extraction or a
  positive attacker match for the LSASS Sigma rule.
- **Not evaluated:** behavior or coverage outside this recorded exercise,
  including the incidental Sandcat thread-creation event.

## LSASS tuning decision

The Sysmon collection filter records accesses to LSASS. That broad collection
is useful for investigation, but a collected event is not automatically an
attacker detection. In this run, the relevant source process was
`MsMpEng.exe`, and Defender recorded the threat and remediation.

The Sigma rule excludes `SourceImage` values containing
`\\Windows Defender\\`. This addresses the observed Defender-path match.
It is a path-based exclusion, not process identity verification. Positive
attacker-access validation of the tuned rule, broader benign testing, and
review of potential blind spots remain future work. No quantified
false-positive reduction is claimed.

## Automated host checks

The [Ansible playbook](../ansible/playbooks/health_check.yml) asserts the Ubuntu
major version and writes host facts to JSON. The
[Python validator](../src/sapphros_validator/validator.py) checks hostnames,
Ubuntu version, minimum memory, and free root storage.

These checks establish specific host prerequisites. They do not check
Caldera service health, Windows telemetry delivery, Sigma alerting, or
ATT&CK detection coverage. The playbook's final message is not a substitute
for running the Python resource checks.

[GitHub Actions](../.github/workflows/python-ci.yml) runs Ruff, four existing
unit tests, and the validator against committed sample reports. It does
not SSH to the physical hosts or rerun the adversary-emulation exercise.

## Evidence boundaries

The published JSON contains selected operation and event excerpts and a
results summary. It is not a complete EVTX export or full Caldera operation
export. For example, the write-up describes two Defender ProcessAccess events
and the absence of a matching ProcessCreate event; the JSON includes one
ProcessAccess excerpt and no complete ProcessCreate search results.

These boundaries limit independent reproduction of those observations. A
future run should preserve sanitized event exports, explicit search windows,
rule evaluation outputs, and collection timestamps alongside its summary.
The existing published event excerpts and historical findings are retained.
