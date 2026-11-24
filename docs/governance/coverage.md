# Coverage matrix

This agent passed every enforced control in the listed packs and holds current attestations for the attested ones. It is not a statement that the organisation is compliant with any law.

| Pack | Enforced | Measured | Attested | Planned (not covered) |
|---|---:|---:|---:|---:|
| eu.ai-act | 3 | 2 | 3 | 0 |
| gov.iso42001 (guidance) | 1 | 0 | 3 | 5 |
| gov.nist-ai-rmf (guidance) | 6 | 3 | 2 | 0 |
| in.icmr | 4 | 2 | 1 | 0 |
| med.cds | 1 | 0 | 0 | 0 |
| med.change | 2 | 0 | 1 | 0 |
| med.fairness | 0 | 0 | 1 | 6 |
| med.grounding | 3 | 1 | 0 | 0 |
| med.hipaa.baa | 3 | 0 | 2 | 1 |
| med.hipaa.breach | 0 | 0 | 0 | 7 |
| med.hipaa.privacy | 12 | 0 | 4 | 8 |
| med.hipaa.records | 0 | 0 | 0 | 5 |
| med.hipaa.security | 4 | 0 | 8 | 5 |
| med.monitor | 2 | 0 | 0 | 0 |
| med.phi | 5 | 0 | 0 | 0 |
| med.research | 6 | 0 | 2 | 13 |
| med.rx | 4 | 0 | 1 | 0 |
| med.sensitive | 7 | 0 | 0 | 8 |
| med.transparency | 0 | 0 | 4 | 3 |
| med.triage | 2 | 0 | 0 | 0 |
| med.trial | 5 | 0 | 0 | 0 |
| reg.eu | 3 | 0 | 5 | 7 |
| reg.india | 2 | 0 | 4 | 9 |
| sec.agent (guidance) | 4 | 0 | 0 | 6 |
| soc2 | 4 | 0 | 7 | 5 |
| **All packs** | **83** | **8** | **48** | **88** |

## Not covered

- FTC Health Breach Notification Rule
- TEFCA and information blocking
- CCPA and other US consumer law
- UK GDPR and the Data Protection Act 2018
- SOC 2 and HITRUST (evidence export only; Shio does not certify)

## Every control

| Pack | Control | Stage | On fail | Coverage | Source |
|---|---|---|---|---|---|
| eu.ai-act | EU-1 Risk management across the lifecycle |  |  | attested | Article 9 |
| eu.ai-act | EU-2 Data governance and bias examination |  |  | measured | Article 10 |
| eu.ai-act | EU-3 Technical documentation |  |  | attested | Article 11, Annex IV |
| eu.ai-act | EU-4 Automatic record-keeping |  |  | enforced | Article 12 |
| eu.ai-act | EU-5 Human oversight |  |  | enforced | Article 14 |
| eu.ai-act | EU-6 Accuracy, robustness and cybersecurity |  |  | measured | Article 15 |
| eu.ai-act | EU-7 Post-market monitoring |  |  | attested | Article 72 |
| eu.ai-act | EU-8 Serious incidents recorded |  |  | enforced | Article 73 |
| gov.iso42001 | A-2 Policies related to AI | X | hold | attested | Annex A.2 |
| gov.iso42001 | A-3 Internal organisation | X | hold | attested | Annex A.3 |
| gov.iso42001 | A-4 Resources | R | hold | enforced | Annex A.4 |
| gov.iso42001 | A-5 Impact assessment and its refresh dates | X | hold | attested | Annex A.5 |
| gov.iso42001 | A-6 Life cycle | R | hold | planned | Annex A.6 |
| gov.iso42001 | A-7 Data provenance | R | hold | planned | Annex A.7 |
| gov.iso42001 | A-8 Information for interested parties | R | hold | planned | Annex A.8 |
| gov.iso42001 | A-9 Use of AI | R | hold | planned | Annex A.9 |
| gov.iso42001 | A-10 Third parties | R | hold | planned | Annex A.10 |
| gov.nist-ai-rmf | GOV-1 Each AI system is inventoried with its intended purpose |  |  | attested | GOVERN 1.6, MAP 1.1 |
| gov.nist-ai-rmf | GOV-2 Model output decides nothing without deterministic rules |  |  | enforced | MANAGE 1.3, MEASURE 2.6 |
| gov.nist-ai-rmf | GOV-3 Models are pinned to exact versions |  |  | enforced | GOVERN 1.4, MANAGE 2.2 |
| gov.nist-ai-rmf | GOV-4 Decisions are recorded, signed and tamper-evident |  |  | enforced | GOVERN 1.4, MEASURE 2.8 |
| gov.nist-ai-rmf | GOV-5 Human oversight of outcomes |  |  | enforced | GOVERN 3.2, MAP 3.5 |
| gov.nist-ai-rmf | GOV-6 Validity and reliability are measured |  |  | measured | MEASURE 2.5 |
| gov.nist-ai-rmf | GOV-7 Performance is compared across subgroups |  |  | measured | MEASURE 2.11 |
| gov.nist-ai-rmf | GOV-8 Adversarial robustness is tested |  |  | measured | MEASURE 2.7 |
| gov.nist-ai-rmf | GOV-9 Privacy risk is controlled for health data |  |  | enforced | MEASURE 2.10 |
| gov.nist-ai-rmf | GOV-10 Third-party components are inventoried and pinned |  |  | enforced | GOVERN 6.1, MAP 4.1 |
| gov.nist-ai-rmf | GOV-11 Post-deployment monitoring is reviewed |  |  | attested | MANAGE 4.1, MEASURE 3.1 |
| in.icmr | ICMR-1 Autonomy: a person stays in control |  |  | enforced | Autonomy |
| in.icmr | ICMR-2 Safety and risk minimisation |  |  | attested | Safety and risk minimization |
| in.icmr | ICMR-3 Trustworthiness: outputs tied to their source |  |  | enforced | Trustworthiness |
| in.icmr | ICMR-4 Data privacy |  |  | enforced | Data privacy |
| in.icmr | ICMR-5 Accountability |  |  | enforced | Accountability and liability |
| in.icmr | ICMR-6 Validity |  |  | measured | Validity |
| in.icmr | ICMR-7 Non-discrimination and fairness |  |  | measured | Non-discrimination and fairness |
| med.cds | CDS-1 Card fits the declared posture |  |  | enforced | CDS-1 to CDS-6 |
| med.change | CHG-1 Releases pin the program and models |  |  | enforced | MANAGE 2.2 |
| med.change | CHG-2 Regression run of the exact release |  |  | enforced | change management |
| med.change | CHG-3 Role sign-off before promotion |  |  | attested | change management |
| med.fairness | FAI-01 An inventory of decision support uses of race | R | hold | planned | 45 CFR 92.210(b) |
| med.fairness | FAI-02 Reasonable efforts to mitigate discrimination risk are recorded | X | hold | attested | 45 CFR 92.210(c) |
| med.fairness | FAI-03 Protected-attribute inputs are declared per agent | P | deny | planned | 45 CFR 92.210 |
| med.fairness | FAI-04 Subgroup sensitivity | R | deny | planned | 45 CFR 92.210 |
| med.fairness | FAI-05 Patient-facing output is tested in the languages and formats served | R | hold | planned | 45 CFR 92.201-205 |
| med.fairness | FAI-06 Proxy variables standing in for a protected class are flagged | R | hold | planned | 45 CFR 92.210 |
| med.fairness | FAI-07 Fairness results are re-run after each change | R | hold | planned | 45 CFR 92.210 |
| med.grounding | GRD-1 Every claim is quoted from the source |  |  | enforced | MEASURE 2.5, hazard control |
| med.grounding | GRD-2 Every figure appears in the source |  |  | enforced | MEASURE 2.5 |
| med.grounding | GRD-3 Required items are not omitted |  |  | enforced | MEASURE 2.5, hazard control |
| med.grounding | GRD-4 Wrongful rejection of good text is measured |  |  | measured | MEASURE 2.5 |
| med.hipaa.baa | BAA-01 Every provider that handles PHI has an agreement on file (PRV-08 enforces it at the gate) | P | route or deny | planned | 164.502(e)(2) |
| med.hipaa.baa | BAA-02 The agreement's scope names the specific service used | P | deny | enforced | 164.504(e) |
| med.hipaa.baa | BAA-03 Agreement terms include the required provisions (counsel reviews the wording) | X | hold | attested | 164.504(e)(2) |
| med.hipaa.baa | BAA-04 Each subprocessor has a current flow-down agreement and the profile lists it | P | deny | enforced | 164.502(e)(1)(ii) |
| med.hipaa.baa | BAA-05 The agreement is within its term | P | deny | enforced | 164.504(e) |
| med.hipaa.baa | BAA-06 Providers that are not business associates are recorded as such | X | hold | attested | 164.502(e) |
| med.hipaa.breach | BRE-01 An impermissible use is presumed a breach unless a documented four-factor assessment shows | R | hold | planned | 164.402 |
| med.hipaa.breach | BRE-02 Each store and channel records whether HHS-recognised protection applies (unsecured PHI) | R | hold | planned | 164.402 |
| med.hipaa.breach | BRE-03 An incident starts a notification clock at discovery: individuals within 60 calendar days | R | hold | planned | 164.404 |
| med.hipaa.breach | BRE-04 500 or more | R | hold | planned | 164.406, 164.408 |
| med.hipaa.breach | BRE-05 A business associate notifies the covered entity within 60 days | R | hold | planned | 164.410 |
| med.hipaa.breach | BRE-06 Shorter state breach deadlines from the state table replace the federal one | R | hold | planned | state law |
| med.hipaa.breach | BRE-07 Every notification | R | deny | planned | 164.414 |
| med.hipaa.privacy | PRV-01 Every request declares a purpose from the registry | P | deny | enforced | 164.502(a), 164.506 |
| med.hipaa.privacy | PRV-02 Purposes that need written authorization (marketing | P | hold | enforced | 164.508(a) |
| med.hipaa.privacy | PRV-03 An authorization relied on is signed | P | deny | enforced | 164.508(c) |
| med.hipaa.privacy | PRV-04 Minimum necessary | P | redact | enforced | 164.502(b), 164.514(d) |
| med.hipaa.privacy | PRV-05 Minimum-necessary exceptions are explicit and narrow | P | deny | planned | 164.502(b)(2) |
| med.hipaa.privacy | PRV-06 A whole-record request carries a written justification | P | hold | enforced | 164.514(d)(5) |
| med.hipaa.privacy | PRV-07 Each caller has a role | P | deny | enforced | 164.514(d)(2) |
| med.hipaa.privacy | PRV-08 PHI goes only to parties with a business associate agreement on file | P | route or deny | enforced | 164.502(e), 164.504(e) |
| med.hipaa.privacy | PRV-09 Where the purpose needs no PHI | P | redact | enforced | 164.514(a), (b) |
| med.hipaa.privacy | PRV-10 Re-identification codes are not derived from identifiers and the key stays outside the mod | P | deny | planned | 164.514(c) |
| med.hipaa.privacy | PRV-11 A limited data set has a current data use agreement with the recipient | P | hold | enforced | 164.514(e) |
| med.hipaa.privacy | PRV-12 Research names exactly one pathway | P | hold | enforced | 164.512(i) |
| med.hipaa.privacy | PRV-13 Disclosures to a personal representative need a representative record and respect state ru | P | hold | planned | 164.502(g) |
| med.hipaa.privacy | PRV-14 Restrictions and confidential communications the organisation agreed to are honoured | P | deny | enforced | 164.522 |
| med.hipaa.privacy | PRV-15 Opt-outs and fundraising or marketing preferences are applied | P | deny | enforced | 164.514(f), 164.508(a)(3) |
| med.hipaa.privacy | PRV-16 Disclosures to the individual go through the right-of-access path with identity verificati | A | hold | planned | 164.524, 164.514(h) |
| med.hipaa.privacy | PRV-17 Every non-TPO disclosure is logged for accounting and kept six years | R | deny | planned | 164.528 |
| med.hipaa.privacy | PRV-18 Amendment requests are routed to a person and tracked to a decision | A | hold | attested | 164.526 |
| med.hipaa.privacy | PRV-19 The Notice of Privacy Practices is current and covers AI use where required | X | hold | attested | 164.520 |
| med.hipaa.privacy | PRV-20 Documentation | X | hold | attested | 164.530(j) |
| med.hipaa.privacy | PRV-21 Workforce training | X | hold | attested | 164.530(a)-(f) |
| med.hipaa.privacy | PRV-22 Safeguards for PHI in prompts | R | deny | planned | 164.530(c) |
| med.hipaa.privacy | PRV-23 A harmful impermissible use opens a mitigation record | R | hold | planned | 164.530(f) |
| med.hipaa.privacy | PRV-24 Identity and authority are verified before disclosing outside the organisation | A | hold | planned | 164.514(h) |
| med.hipaa.records | REC-01 HIPAA documentation and accounting records are kept six years | R | deny | planned | 164.316(b)(2), 164.530(j) |
| med.hipaa.records | REC-02 Medical record retention follows the longest applicable period | R | deny | planned | state law |
| med.hipaa.records | REC-03 Prompts | R | deny | planned | 164.530(c) |
| med.hipaa.records | REC-04 Access requests are timed (30 days plus one extension) and fulfilled from the record of tr | A | hold | planned | 164.524 |
| med.hipaa.records | REC-05 Erasure is coordinated with legal hold and retention so required records survive | R | hold | planned | 164.524, 164.530(j) |
| med.hipaa.security | SEC-01 A current security risk analysis covers the agent | X | deny | attested | 164.308(a)(1)(ii)(A) |
| med.hipaa.security | SEC-02 A risk management plan records the measures taken against each risk found | X | hold | attested | 164.308(a)(1)(ii)(B) |
| med.hipaa.security | SEC-03 Audit records are reviewed on a schedule by a named role | X | hold | attested | 164.308(a)(1)(ii)(D) |
| med.hipaa.security | SEC-04 Security official | X | hold | attested | 164.308(a)(2)-(5) |
| med.hipaa.security | SEC-05 Security incident procedures exist and agent incidents are recorded as events | R | hold | planned | 164.308(a)(6) |
| med.hipaa.security | SEC-06 The contingency plan covers the agent | X | hold | attested | 164.308(a)(7) |
| med.hipaa.security | SEC-07 Periodic evaluation | X | hold | attested | 164.308(a)(8) |
| med.hipaa.security | SEC-08 Every caller has a unique identity | P | deny | enforced | 164.312(a)(2)(i) |
| med.hipaa.security | SEC-09 Emergency access is documented | A | hold | planned | 164.312(a)(2)(ii) |
| med.hipaa.security | SEC-10 Interactive sessions log off automatically | R | deny | planned | 164.312(a)(2)(iii) |
| med.hipaa.security | SEC-11 PHI at rest in vaults | R | deny | planned | 164.312(a)(2)(iv) |
| med.hipaa.security | SEC-12 Every PHI access and model call produces a signed | R | deny | enforced | 164.312(b) |
| med.hipaa.security | SEC-13 Stored PHI and records are protected from alteration | R | deny | planned | 164.312(c) |
| med.hipaa.security | SEC-14 Callers and tools are authenticated | P | deny | enforced | 164.312(d) |
| med.hipaa.security | SEC-15 Model and tool endpoints use TLS | P | deny | enforced | 164.312(e) |
| med.hipaa.security | SEC-16 Physical safeguards are attested for every site hosting the runtime | X | hold | attested | 164.310 |
| med.hipaa.security | SEC-17 Security policies and documentation are retained six years | X | hold | attested | 164.316(b) |
| med.monitor | MON-1 Metrics sliced by group and site |  |  | enforced | MEASURE 2.11, monitoring |
| med.monitor | MON-2 Safety events are records |  |  | enforced | incident management, MANAGE 4.3 |
| med.phi | PHI-1 Safe Harbor identifiers removed from outputs |  |  | enforced | 164.514(b)(2) |
| med.phi | PHI-2 Only models approved for PHI receive it |  |  | enforced | 164.502(e) |
| med.phi | PHI-3 Minimum necessary fields |  |  | enforced | 164.502(b) |
| med.phi | PHI-4 Expert determination on file when used |  |  | enforced | 164.514(b)(1) |
| med.phi | PHI-5 PHI stays out of records except the vault |  |  | enforced | 164.530(c) |
| med.research | RES-01 Each research request carries a study ID that resolves to a registered study | P | deny | enforced | 45 CFR 46 |
| med.research | RES-02 IRB approval is current at the time of the call | P | deny | enforced | 45 CFR 46.109, 21 CFR 56.109 |
| med.research | RES-03 Only fields in the approved protocol's data list are sent | P | redact | enforced | 45 CFR 46 |
| med.research | RES-04 Informed consent in the current approved version is on file and not withdrawn | P | hold | enforced | 45 CFR 46.116, 21 CFR 50 |
| med.research | RES-05 Waived-consent studies carry the waiver determination | P | hold | planned | 45 CFR 46.116(f) |
| med.research | RES-06 Broad consent for secondary research is respected | P | hold | planned | 45 CFR 46.116(d) |
| med.research | RES-07 Data from a withdrawn participant is excluded going forward | P | deny | enforced | 45 CFR 46 |
| med.research | RES-08 Vulnerable populations trigger the protections recorded in the approval | P | hold | planned | 45 CFR 46 subparts B-D |
| med.research | RES-09 Research disclosures under a waiver are logged for accounting | R | deny | planned | 164.528 |
| med.research | RES-10 The model call is a listed processing step in the protocol or plan | P | hold | planned | data management plan |
| med.research | RES-11 Computerised systems for trial data meet Part 11: validation | R | deny | planned | 21 CFR Part 11 |
| med.research | RES-12 Model-derived values are marked as such and never overwrite source data | R | deny | planned | ALCOA+ |
| med.research | RES-13 Sponsor | X | hold | attested | ICH E6(R3) |
| med.research | RES-14 Unblinding is a human | A | deny | planned | ICH E6(R3) |
| med.research | RES-15 Adverse events the agent finds reach the safety role within the protocol's timeline | O | hold | planned | 21 CFR 312.32 |
| med.research | RES-16 Protocol deviations the agent causes are logged | R | hold | planned | ICH E6(R3) |
| med.research | RES-17 Eligibility output is signed off by the investigator before anyone is contacted | A | hold | enforced | 21 CFR 312.60 |
| med.research | RES-18 Recruitment messages use IRB-approved text only | A | deny | planned | 45 CFR 46.111 |
| med.research | RES-19 Data sharing and publication follow the study's plan and any certificate of confidentialit | A | hold | planned | data-sharing plan |
| med.research | RES-20 Registration and results-reporting dates are attested | X | hold | attested | 42 CFR Part 11 (ClinicalTrials.gov) |
| med.research | RES-21 Study records are kept for the longest applicable period | R | deny | planned | 21 CFR 312.62 |
| med.rx | RX-1 Drug resolved to a standard code |  |  | enforced | hazard control |
| med.rx | RX-2 Dose recomputed in code |  |  | enforced | hazard control |
| med.rx | RX-3 Interactions looked up |  |  | enforced | hazard control |
| med.rx | RX-4 Allergies looked up |  |  | enforced | hazard control |
| med.rx | RX-5 Reference data licensing confirmed |  |  | attested | hazard control |
| med.sensitive | SEN-01 Part 2 records are labelled at ingestion and the label travels with everything derived fro | P | deny | planned | 42 CFR Part 2 |
| med.sensitive | SEN-02 Use of Part 2 records needs written consent on file for this purpose | P | hold | enforced | 42 CFR 2.31 |
| med.sensitive | SEN-03 Records received under a Part 2 consent carry the redisclosure notice | O | hold | planned | 42 CFR 2.32 |
| med.sensitive | SEN-04 Part 2 records are never used in proceedings against the patient without a qualifying cour | P | deny | enforced | 42 CFR 2.12 |
| med.sensitive | SEN-05 The provider is a qualified service organisation or has a Part 2 flow-down agreement | P | deny | enforced | 42 CFR 2.11 |
| med.sensitive | SEN-06 Breach of Part 2 records follows the HIPAA breach pack | R | hold | planned | 42 CFR 2.16 |
| med.sensitive | SEN-07 Psychotherapy notes are blocked from every model call by default | P | deny | enforced | 164.501, 164.508(a)(2) |
| med.sensitive | SEN-08 The classifier distinguishes psychotherapy notes from ordinary mental health records | P | hold | planned | 164.501 |
| med.sensitive | SEN-09 Reproductive health data follows state shield or restriction laws from the state table (th | P | hold | planned | state law |
| med.sensitive | SEN-10 Genetic data is never used for underwriting or employment | P | deny | enforced | state genetic privacy law |
| med.sensitive | SEN-11 For minors | P | hold | enforced | state law |
| med.sensitive | SEN-12 A versioned state table with cited | P | hold | enforced | state law |
| med.sensitive | SEN-13 Data from several states in one request | P | hold | planned | state law |
| med.sensitive | SEN-14 Other protected categories are custom classes that default to Deny until a pack authorises | P | deny | planned | state law |
| med.sensitive | SEN-15 Free text is scanned for sensitive classes the structured fields don't carry | P | hold | planned | state law |
| med.transparency | TRN-01 Patient-facing generative output says AI produced it and how to reach a human | O | deny | planned | state law |
| med.transparency | TRN-02 Clinician-facing readings show the model | O | hold | planned | ONC HTI-1 |
| med.transparency | TRN-03 A model card per profile records intended use | X | hold | attested | NIST AI RMF |
| med.transparency | TRN-04 Source attributes of predictive decision support interventions in listed health IT are sto | X | hold | attested | 45 CFR 170.315(b)(11) |
| med.transparency | TRN-05 Patients can learn AI was used in their care (links to PRV-19) | X | hold | attested | 164.520 |
| med.transparency | TRN-06 Significant automated decisions state their logic plainly and offer human review | O | hold | planned | GDPR Art. 22 |
| med.transparency | TRN-07 Staff and patients can report an AI incident through a documented channel | X | hold | attested | Joint Commission and CHAI (guidance) |
| med.triage | TRI-1 Red flags run in code before the model |  |  | enforced | hazard control |
| med.triage | TRI-2 Out-of-scope requests refused |  |  | enforced | hazard control |
| med.trial | TRL-1 Eligibility decided in code |  |  | enforced | investigator responsibilities: eligibility |
| med.trial | TRL-2 Blinding kept from models |  |  | enforced | blinding |
| med.trial | TRL-3 Protocol deviations caught |  |  | enforced | protocol compliance |
| med.trial | TRL-4 Adverse-event reporting clocks |  |  | enforced | expedited reporting timeframes |
| med.trial | TRL-5 Consent version current |  |  | enforced | informed consent |
| reg.eu | EU-01 Health data has an Article 6 basis and an Article 9 condition | P | deny | enforced | GDPR Art. 6, 9 |
| reg.eu | EU-02 Fields are limited to the purpose | P | redact | planned | GDPR Art. 5 |
| reg.eu | EU-03 A processor agreement is in force with each model provider and subprocessor | P | deny | enforced | GDPR Art. 28 |
| reg.eu | EU-04 Transfers outside the EEA have an adequacy decision | P | route or deny | enforced | GDPR Chapter V |
| reg.eu | EU-05 A data protection impact assessment is on file | X | hold | attested | GDPR Art. 35 |
| reg.eu | EU-06 Significant automated decisions have human involvement and can be contested | O | hold | planned | GDPR Art. 22 |
| reg.eu | EU-07 Data subject rights are routed within one month | A | hold | planned | GDPR Art. 15-22 |
| reg.eu | EU-08 Breach notice to the authority within 72 hours where required | R | hold | planned | GDPR Art. 33, 34 |
| reg.eu | EU-09 Records of processing are generated from the agent card | R | deny | planned | GDPR Art. 30 |
| reg.eu | EU-10 The AI Act risk class and the date its obligations apply are recorded (stand-alone high-ri | X | hold | attested | AI Act |
| reg.eu | EU-11 High-risk obligations are mapped to the Shio controls that produce their evidence | R | hold | planned | AI Act Title III |
| reg.eu | EU-12 Transparency duties for systems that interact with people apply where in force | O | hold | planned | AI Act Art. 50 |
| reg.eu | EU-13 Medical device agents attach their change plan and clinical evaluation | X | hold | attested | MDR 2017/745 |
| reg.eu | EU-14 EU clinical trials follow the Clinical Trials Regulation | X | hold | attested | CTR 536/2014 |
| reg.eu | EU-15 European Health Data Space duties are tracked as they apply | X | hold | attested | EHDS |
| reg.india | IN-01 Notice and specific | P | deny | enforced | DPDP Act s.6 |
| reg.india | IN-02 Processing is limited to the consented purpose | P | redact | planned | DPDP Act s.4-6 |
| reg.india | IN-03 A processor (including a model provider) acts under a valid contract | P | deny | planned | DPDP Act s.8(2) |
| reg.india | IN-04 Reasonable safeguards | R | hold | planned | DPDP Act s.8(6) |
| reg.india | IN-05 Erasure when the purpose ends or consent is withdrawn | R | hold | planned | DPDP Act s.8(7) |
| reg.india | IN-06 Verifiable parental or guardian consent where required | P | hold | planned | DPDP Act s.9 |
| reg.india | IN-07 Significant data fiduciary duties are tracked where designated | X | hold | attested | DPDP Act s.10 |
| reg.india | IN-08 No transfer to a country on the government's restricted list | P | route or deny | enforced | DPDP Act s.16 |
| reg.india | IN-09 Use of the research exemption is recorded with its conditions | P | hold | planned | DPDP Act s.17 |
| reg.india | IN-10 The ICMR AI principles are mapped to Shio controls and ethics review is attested | X | hold | attested | ICMR 2023 |
| reg.india | IN-11 Ethics committee approval | X | hold | attested | ICMR 2017, NDCT Rules 2019 |
| reg.india | IN-12 ABDM consent artefacts are verified before records are used | P | deny | planned | ABDM |
| reg.india | IN-13 Software-as-medical-device classification and licence status are recorded | X | hold | attested | CDSCO |
| reg.india | IN-14 Cyber incidents are reported within CERT-In's period | R | hold | planned | CERT-In directions |
| reg.india | IN-15 The registered practitioner stays responsible | A | deny | planned | Telemedicine Practice Guidelines 2020 |
| sec.agent | ASI-01 Goal hijack | P | deny | enforced | ASI01 |
| sec.agent | ASI-02 Tool misuse | A | hold | enforced | ASI02 |
| sec.agent | ASI-03 Each agent has its own least-privilege identity | A | deny | planned | ASI03 |
| sec.agent | ASI-04 Supply chain | R | deny | enforced | ASI04 |
| sec.agent | ASI-05 No model-written code runs | A | deny | enforced | ASI05 |
| sec.agent | ASI-06 Memory writes are typed | R | hold | planned | ASI06 |
| sec.agent | ASI-07 Messages between agents are signed | A | deny | planned | ASI07 |
| sec.agent | ASI-08 Circuit breakers | A | hold | planned | ASI08 |
| sec.agent | ASI-09 Readings show their basis | O | hold | planned | ASI09 |
| sec.agent | ASI-10 Signed records | R | deny | planned | ASI10 |
| soc2 | CC-1 Control environment | X | hold | attested | CC1.1-CC1.5 |
| soc2 | CC-2 Information and communication | X | hold | attested | CC2.1-CC2.3 |
| soc2 | CC-3 Risk assessment | X | hold | attested | CC3.1-CC3.4 |
| soc2 | CC-4 Monitoring activities | R | hold | planned | CC4.1-CC4.2 |
| soc2 | CC-5 Control activities are selected | X | hold | attested | CC5.1-CC5.3 |
| soc2 | CC-6 Logical access | P | deny | planned | CC6.1 |
| soc2 | CC-7 Transmission and boundary protection | R | deny | planned | CC6.6-CC6.7 |
| soc2 | CC-8 Unauthorised or malicious software is prevented: pinned dependencies | R | deny | enforced | CC6.8 |
| soc2 | CC-9 System operations | R | hold | planned | CC7.1-CC7.2 |
| soc2 | CC-10 Incidents are evaluated | R | hold | planned | CC7.3-CC7.5 |
| soc2 | CC-11 Change management | R | deny | enforced | CC8.1 |
| soc2 | CC-12 Risk mitigation | X | hold | attested | CC9.1-CC9.2 |
| soc2 | A-1 Availability | X | hold | attested | A1.1-A1.3 |
| soc2 | C-1 Confidentiality | R | deny | enforced | C1.1-C1.2 |
| soc2 | PI-1 Processing integrity | R | deny | enforced | PI1.1-PI1.5 |
| soc2 | P-1 Privacy | X | hold | attested | P1-P8 |
