# D36: Shio 1.0 and Shio Guard, release checklist

Shio 1.0.0 is final when the criteria in [the changelog](https://github.com/pratikkp24/shio/blob/main/CHANGELOG.md) (1.0.0rc1) are met: an outside security
review of the boundary, at least one production deployment, and the benchmark results on Haiku 5.5. Shio Guard adds
the items below. **None of the human items can be ticked by engineering.**

## Automated (CI, every push)

- [x] Full test suite, including every Shio Guard deliverable's "done when" test (`tests/test_governance_*.py`)
- [x] Every built-in pack validates, fixtures run (`shio pack validate`)
- [x] Licence policy check (`shio licences check --extra regulated --extra pdf`)
- [x] Red-team suite derived from every pack's adversarial fixtures (`shio pack redteam` + `shio eval`)
- [x] Reference agents' cards build and their assessments prove every applicable control
- [x] Reference agents' eval suites meet their gates

## People (the plan's required roles)

- [ ] Founders sign the decision record (D1)
- [ ] Regulatory counsel approves the licence policy and the typing-extensions exception (D4)
- [ ] Counsel reviews the wording of `gov.nist-ai-rmf`, `eu.ai-act`, `in.icmr`, and the `med.cds` constraints
- [ ] Clinical safety lead reviews every `med.*` pack (status `reviewed` requires their name and date)
- [ ] Clinical safety lead approves the red-flag list (an approval of its sha256)
- [ ] Clinical safety lead builds and labels the grounding set; rates republished from it (D15, D16)
- [ ] Clinical safety lead reviews and approves the reference agents' safety cases (D24)
- [ ] Clinical design partner reviews reference agent 2 end to end (D26)
- [ ] Reference-data licences confirmed before any real drug data is loaded (D20)
- [ ] A Credo AI tenant to verify the export sink's endpoints and payloads (D33)
- [ ] DPDP Act and CDSCO research, then counsel-reviewed packs (D34)
- [ ] Outside security review, including the governance threat-model section (§8) and the console
- [ ] A first production deployment
