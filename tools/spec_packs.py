"""Generate the policy pack specification's packs (v0.1.0, draft) from one catalogue.

    python tools/spec_packs.py            # writes shio/packs/<id>/pack.json and README.md for each pack below

Each row is the spec's control: id | stage | proof | on fail | source | requirement (in this project's words). The
proof a pack.json gets is decided here, never claimed:

  gate         the pre-model gate enforces it (shio.governance.preflight.controls has the control, with fixtures
               and a mutation test, and `shio pack validate` runs them)
  lint         shio assess already proves it statically (the LINT table below)
  attestation  stage X with a sign-off proof: the gate requires a current signed attestation
  signoff      a person in a role signs it off (A/R-stage sign-offs)
  planned      everything else: listed so the coverage matrix shows it, and not yet built

Rows are paraphrased from the spec (Shio policy pack specification, 24 Nov 2026), which summarises primary sources
checked in November 2026. Counsel re-reads the primary text before any pack becomes `reviewed`.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shio.governance.preflight.controls import REGISTRY  # noqa: E402

EFFECTIVE = "2026-11-24"
LINT = {"soc2:CC-8": "dependencies-pinned", "soc2:CC-11": "models-pinned", "soc2:C-1": "regulated-mode",
        "soc2:PI-1": "readings-through-rules", "sec.agent:ASI-01": "readings-through-rules", "sec.agent:ASI-02": "tools-gated",
        "sec.agent:ASI-04": "dependencies-pinned", "sec.agent:ASI-05": "no-reflection",
        "med.hipaa.security:SEC-12": "regulated-mode", "med.hipaa.security:SEC-14": "models-pinned",
        "med.research:RES-17": "signoff-required", "gov.iso42001:A-4": "pack-wired"}
ATTEST_KIND = {"med.hipaa.security:SEC-01": "security-risk-analysis", "med.hipaa.privacy:PRV-21": "privacy-program",
               "med.hipaa.baa:BAA-03": "baa-terms-reviewed"}
VALID = 365

PACKS = {
 "med.hipaa.privacy": ("HIPAA Privacy Rule: purpose, authorization, minimum necessary, de-identification and disclosures",
   "hipaa-privacy", "HIPAA Privacy Rule (45 CFR Part 164, Subpart E)", "privacy_officer", """
PRV-01|P|lint, check|Deny|164.502(a), 164.506|Every request declares a purpose from the registry; uses and disclosures are allowed only as the Rule permits.
PRV-02|P|check|Hold|164.508(a)|Purposes that need written authorization (marketing, sale of PHI, psychotherapy notes) have a matching, unexpired authorization.
PRV-03|P|check|Deny|164.508(c)|An authorization relied on is signed, dated, names the information, recipient, purpose and expiry, carries the revocation statement and is not revoked.
PRV-04|P|lint, check|Redact|164.502(b), 164.514(d)|Minimum necessary: only fields on the purpose's allow-list are sent.
PRV-05|P|lint|Deny|164.502(b)(2)|Minimum-necessary exceptions are explicit and narrow; nothing else is exempt.
PRV-06|P|check|Hold|164.514(d)(5)|A whole-record request carries a written justification.
PRV-07|P|check|Deny|164.514(d)(2)|Each caller has a role, and each role a list of PHI categories it may read.
PRV-08|P|check, sign-off|Route or Deny|164.502(e), 164.504(e)|PHI goes only to parties with a business associate agreement on file, that do not train on inputs, and are approved for the data classes sent.
PRV-09|P|check, eval|Redact|164.514(a), (b)|Where the purpose needs no PHI, identifiers are de-identified (tokenised) before sending, and a second detector pass holds anything left.
PRV-10|P|check|Deny|164.514(c)|Re-identification codes are not derived from identifiers and the key stays outside the model boundary.
PRV-11|P|check|Hold|164.514(e)|A limited data set has a current data use agreement with the recipient.
PRV-12|P|check|Hold|164.512(i)|Research names exactly one pathway, with its proof on file.
PRV-13|P|check|Hold|164.502(g)|Disclosures to a personal representative need a representative record and respect state rules on minors.
PRV-14|P|check|Deny|164.522|Restrictions and confidential communications the organisation agreed to are honoured.
PRV-15|P|check|Deny|164.514(f), 164.508(a)(3)|Opt-outs and fundraising or marketing preferences are applied.
PRV-16|A|check|Hold|164.524, 164.514(h)|Disclosures to the individual go through the right-of-access path with identity verification.
PRV-17|R|check|Deny|164.528|Every non-TPO disclosure is logged for accounting and kept six years.
PRV-18|A|sign-off|Hold|164.526|Amendment requests are routed to a person and tracked to a decision.
PRV-19|X|sign-off|Hold|164.520|The Notice of Privacy Practices is current and covers AI use where required.
PRV-20|X|sign-off|Hold|164.530(j)|Documentation, policies and training records are kept six years.
PRV-21|X|sign-off|Hold|164.530(a)-(f)|Workforce training, a sanctions policy and a named privacy official exist.
PRV-22|R|check|Deny|164.530(c)|Safeguards for PHI in prompts, logs, traces, caches and eval sets are no weaker than for production records.
PRV-23|R|check|Hold|164.530(f)|A harmful impermissible use opens a mitigation record.
PRV-24|A|check|Hold|164.514(h)|Identity and authority are verified before disclosing outside the organisation."""),
 "med.hipaa.security": ("HIPAA Security Rule: risk analysis, access, audit, integrity and transmission security",
   "hipaa-security", "HIPAA Security Rule (45 CFR 164.308 to 164.316)", "security_officer", """
SEC-01|X|sign-off|Deny|164.308(a)(1)(ii)(A)|A current security risk analysis covers the agent, its model destinations, tools and stores.
SEC-02|X|sign-off|Hold|164.308(a)(1)(ii)(B)|A risk management plan records the measures taken against each risk found.
SEC-03|X|sign-off|Hold|164.308(a)(1)(ii)(D)|Audit records are reviewed on a schedule by a named role.
SEC-04|X|sign-off|Hold|164.308(a)(2)-(5)|Security official, workforce security, access management and awareness training attestations are current.
SEC-05|R|check, sign-off|Hold|164.308(a)(6)|Security incident procedures exist and agent incidents are recorded as events.
SEC-06|X|sign-off|Hold|164.308(a)(7)|The contingency plan covers the agent: backups, disaster recovery and emergency mode.
SEC-07|X|sign-off|Hold|164.308(a)(8)|Periodic evaluation, repeated after a change (a model version change counts).
SEC-08|P|check|Deny|164.312(a)(2)(i)|Every caller has a unique identity; no shared service account reaches PHI.
SEC-09|A|check, sign-off|Hold|164.312(a)(2)(ii)|Emergency access is documented, limited to named roles, logged and reviewed.
SEC-10|R|lint|Deny|164.312(a)(2)(iii)|Interactive sessions log off automatically.
SEC-11|R|check|Deny|164.312(a)(2)(iv)|PHI at rest in vaults, traces, caches and eval sets is encrypted.
SEC-12|R|check|Deny|164.312(b)|Every PHI access and model call produces a signed, hash-chained record.
SEC-13|R|check|Deny|164.312(c)|Stored PHI and records are protected from alteration; chain verification passes.
SEC-14|P|check|Deny|164.312(d)|Callers and tools are authenticated; model destinations are pinned to a version.
SEC-15|P|check|Deny|164.312(e)|Model and tool endpoints use TLS; plain HTTP is refused.
SEC-16|X|sign-off|Hold|164.310|Physical safeguards are attested for every site hosting the runtime.
SEC-17|X|sign-off|Hold|164.316(b)|Security policies and documentation are retained six years."""),
 "med.hipaa.baa": ("HIPAA business associate agreements for every model, tool and storage provider",
   "hipaa-baa", "HIPAA business associate requirements (164.502(e), 164.504(e), 164.314(a))", "privacy_officer", """
BAA-01|P|check|Route or Deny|164.502(e)(2)|Every provider that handles PHI has an agreement on file (PRV-08 enforces it at the gate).
BAA-02|P|check|Deny|164.504(e)|The agreement's scope names the specific service used, and the profile references it.
BAA-03|X|sign-off|Hold|164.504(e)(2)|Agreement terms include the required provisions (counsel reviews the wording).
BAA-04|P|check|Deny|164.502(e)(1)(ii)|Each subprocessor has a current flow-down agreement and the profile lists it.
BAA-05|P|check|Deny|164.504(e)|The agreement is within its term: a warning 60 days out, Deny the day it lapses.
BAA-06|X|sign-off|Hold|164.502(e)|Providers that are not business associates are recorded as such, with the reasoning."""),
 "med.hipaa.breach": ("HIPAA Breach Notification Rule: presumption, clocks and notices",
   "hipaa-breach", "HIPAA Breach Notification Rule (164.400 to 164.414)", "privacy_officer", """
BRE-01|R|check, sign-off|Hold|164.402|An impermissible use is presumed a breach unless a documented four-factor assessment shows low probability of compromise.
BRE-02|R|check|Hold|164.402|Each store and channel records whether HHS-recognised protection applies (unsecured PHI).
BRE-03|R|check|Hold|164.404|An incident starts a notification clock at discovery: individuals within 60 calendar days.
BRE-04|R|check|Hold|164.406, 164.408|500 or more: HHS and media within 60 days; fewer: logged and reported within 60 days of year end.
BRE-05|R|check|Hold|164.410|A business associate notifies the covered entity within 60 days, or the agreement's shorter period.
BRE-06|R|check|Hold|state law|Shorter state breach deadlines from the state table replace the federal one.
BRE-07|R|check|Deny|164.414|Every notification, risk assessment and delay is signed and retained six years."""),
 "med.hipaa.records": ("HIPAA retention, access rights and deletion",
   "hipaa-records", "HIPAA retention and rights (164.316, 164.524, 164.526, 164.528, 164.530)", "privacy_officer", """
REC-01|R|check|Deny|164.316(b)(2), 164.530(j)|HIPAA documentation and accounting records are kept six years; the vault enforces the floor.
REC-02|R|check|Deny|state law|Medical record retention follows the longest applicable period; earlier deletion is refused.
REC-03|R|check|Deny|164.530(c)|Prompts, completions and traces with PHI inherit their record class's retention, and no longer.
REC-04|A|check|Hold|164.524|Access requests are timed (30 days plus one extension) and fulfilled from the record of truth.
REC-05|R|check|Hold|164.524, 164.530(j)|Erasure is coordinated with legal hold and retention so required records survive."""),
 "med.sensitive": ("Sensitive health data: Part 2, psychotherapy notes, reproductive, genetic, minors and state law",
   "sensitive", "42 CFR Part 2, 45 CFR 164.501 and 164.508(a)(2), state health privacy law", "privacy_officer", """
SEN-01|P|check|Deny|42 CFR Part 2|Part 2 records are labelled at ingestion and the label travels with everything derived from them.
SEN-02|P|check|Hold|42 CFR 2.31|Use of Part 2 records needs written consent on file for this purpose, not revoked.
SEN-03|O|check|Hold|42 CFR 2.32|Records received under a Part 2 consent carry the redisclosure notice.
SEN-04|P|lint|Deny|42 CFR 2.12|Part 2 records are never used in proceedings against the patient without a qualifying court order.
SEN-05|P|check|Deny|42 CFR 2.11|The provider is a qualified service organisation or has a Part 2 flow-down agreement.
SEN-06|R|check|Hold|42 CFR 2.16|Breach of Part 2 records follows the HIPAA breach pack.
SEN-07|P|check|Deny|164.501, 164.508(a)(2)|Psychotherapy notes are blocked from every model call by default.
SEN-08|P|eval|Hold|164.501|The classifier distinguishes psychotherapy notes from ordinary mental health records; mislabels are logged.
SEN-09|P|check|Hold|state law|Reproductive health data follows state shield or restriction laws from the state table (the 2024 federal rule was vacated in June 2025).
SEN-10|P|check|Deny|state genetic privacy law|Genetic data is never used for underwriting or employment.
SEN-11|P|check|Hold|state law|For minors, consent follows the state's rule for the type of care.
SEN-12|P|lint, sign-off|Hold|state law|A versioned state table with cited, reviewed rows; rows older than twelve months are stale and unreviewed states hold.
SEN-13|P|check|Hold|state law|Data from several states in one request: the strictest rule wins.
SEN-14|P|lint|Deny|state law|Other protected categories are custom classes that default to Deny until a pack authorises them.
SEN-15|P|eval|Hold|state law|Free text is scanned for sensitive classes the structured fields don't carry."""),
 "med.research": ("Research use, human subjects and trial data",
   "research", "HIPAA 164.512(i), 45 CFR 46, 21 CFR 50, 56, Part 11, ICH E6(R3)", "irb_liaison", """
RES-01|P|check|Deny|45 CFR 46|Each research request carries a study ID that resolves to a registered study.
RES-02|P|check|Deny|45 CFR 46.109, 21 CFR 56.109|IRB approval is current at the time of the call.
RES-03|P|check|Redact|45 CFR 46|Only fields in the approved protocol's data list are sent.
RES-04|P|check|Hold|45 CFR 46.116, 21 CFR 50|Informed consent in the current approved version is on file and not withdrawn.
RES-05|P|check|Hold|45 CFR 46.116(f)|Waived-consent studies carry the waiver determination.
RES-06|P|check|Hold|45 CFR 46.116(d)|Broad consent for secondary research is respected.
RES-07|P|check|Deny|45 CFR 46|Data from a withdrawn participant is excluded going forward.
RES-08|P|check|Hold|45 CFR 46 subparts B-D|Vulnerable populations trigger the protections recorded in the approval.
RES-09|R|check|Deny|164.528|Research disclosures under a waiver are logged for accounting.
RES-10|P|check|Hold|data management plan|The model call is a listed processing step in the protocol or plan.
RES-11|R|check, sign-off|Deny|21 CFR Part 11|Computerised systems for trial data meet Part 11: validation, audit trails, access limits, linked signatures.
RES-12|R|check|Deny|ALCOA+|Model-derived values are marked as such and never overwrite source data.
RES-13|X|sign-off|Hold|ICH E6(R3)|Sponsor, investigator and vendor responsibilities for the agent are recorded.
RES-14|A|check|Deny|ICH E6(R3)|Unblinding is a human, role-restricted action; the agent can't reach treatment allocation.
RES-15|O|check|Hold|21 CFR 312.32|Adverse events the agent finds reach the safety role within the protocol's timeline.
RES-16|R|check|Hold|ICH E6(R3)|Protocol deviations the agent causes are logged.
RES-17|A|sign-off|Hold|21 CFR 312.60|Eligibility output is signed off by the investigator before anyone is contacted.
RES-18|A|check|Deny|45 CFR 46.111|Recruitment messages use IRB-approved text only.
RES-19|A|check|Hold|data-sharing plan|Data sharing and publication follow the study's plan and any certificate of confidentiality.
RES-20|X|sign-off|Hold|42 CFR Part 11 (ClinicalTrials.gov)|Registration and results-reporting dates are attested.
RES-21|R|check|Deny|21 CFR 312.62|Study records are kept for the longest applicable period."""),
 "reg.eu": ("EU: GDPR, the AI Act, the medical device regulations and the European Health Data Space",
   "eu", "GDPR, EU AI Act, MDR/IVDR, Clinical Trials Regulation, EHDS", "data_protection_officer", """
EU-01|P|check|Deny|GDPR Art. 6, 9|Health data has an Article 6 basis and an Article 9 condition, named on the request.
EU-02|P|check|Redact|GDPR Art. 5|Fields are limited to the purpose; pseudonymised data is still personal data.
EU-03|P|check|Deny|GDPR Art. 28|A processor agreement is in force with each model provider and subprocessor.
EU-04|P|check|Route or Deny|GDPR Chapter V|Transfers outside the EEA have an adequacy decision, SCCs or another mechanism.
EU-05|X|sign-off|Hold|GDPR Art. 35|A data protection impact assessment is on file.
EU-06|O|check|Hold|GDPR Art. 22|Significant automated decisions have human involvement and can be contested.
EU-07|A|check|Hold|GDPR Art. 15-22|Data subject rights are routed within one month.
EU-08|R|check|Hold|GDPR Art. 33, 34|Breach notice to the authority within 72 hours where required.
EU-09|R|check|Deny|GDPR Art. 30|Records of processing are generated from the agent card.
EU-10|X|sign-off|Hold|AI Act|The AI Act risk class and the date its obligations apply are recorded (stand-alone high-risk from 2 Dec 2027, embedded from 2 Aug 2028).
EU-11|R|check, sign-off|Hold|AI Act Title III|High-risk obligations are mapped to the Shio controls that produce their evidence.
EU-12|O|check|Hold|AI Act Art. 50|Transparency duties for systems that interact with people apply where in force.
EU-13|X|sign-off|Hold|MDR 2017/745|Medical device agents attach their change plan and clinical evaluation.
EU-14|X|sign-off|Hold|CTR 536/2014|EU clinical trials follow the Clinical Trials Regulation.
EU-15|X|sign-off|Hold|EHDS|European Health Data Space duties are tracked as they apply."""),
 "reg.india": ("India: the DPDP Act and Rules, ICMR guidelines, ABDM, CDSCO and CERT-In (advisory mode)",
   "india", "DPDP Act 2023 and Rules 2025, ICMR 2017 and 2023, NDCT Rules 2019, ABDM, CDSCO, CERT-In", "data_protection_officer", """
IN-01|P|check|Deny|DPDP Act s.6|Notice and specific, informed consent for each purpose, withdrawable as easily as given.
IN-02|P|check|Redact|DPDP Act s.4-6|Processing is limited to the consented purpose; fields are minimised.
IN-03|P|check|Deny|DPDP Act s.8(2)|A processor (including a model provider) acts under a valid contract.
IN-04|R|check|Hold|DPDP Act s.8(6)|Reasonable safeguards, and breach notice to the Board and each person.
IN-05|R|check|Hold|DPDP Act s.8(7)|Erasure when the purpose ends or consent is withdrawn, unless law requires retention.
IN-06|P|check|Hold|DPDP Act s.9|Verifiable parental or guardian consent where required; no tracking or targeting of children.
IN-07|X|sign-off|Hold|DPDP Act s.10|Significant data fiduciary duties are tracked where designated.
IN-08|P|check|Route or Deny|DPDP Act s.16|No transfer to a country on the government's restricted list.
IN-09|P|check|Hold|DPDP Act s.17|Use of the research exemption is recorded with its conditions.
IN-10|X|sign-off|Hold|ICMR 2023|The ICMR AI principles are mapped to Shio controls and ethics review is attested.
IN-11|X|sign-off|Hold|ICMR 2017, NDCT Rules 2019|Ethics committee approval, consent, compensation and safety reporting for trials.
IN-12|P|check|Deny|ABDM|ABDM consent artefacts are verified before records are used.
IN-13|X|sign-off|Hold|CDSCO|Software-as-medical-device classification and licence status are recorded.
IN-14|R|check|Hold|CERT-In directions|Cyber incidents are reported within CERT-In's period.
IN-15|A|lint|Deny|Telemedicine Practice Guidelines 2020|The registered practitioner stays responsible; the agent never acts as one."""),
 "sec.agent": ("Agent security: the OWASP Top 10 for Agentic Applications (2026); spec ids SEC-A01 to SEC-A10 are ASI-01 to ASI-10 here",
   "owasp-agentic", "OWASP Top 10 for Agentic Applications 2026 (guidance)", "security_officer", """
ASI-01|P|lint, eval|Deny|ASI01|Goal hijack: model output is a reading and can't choose tools or targets; only code and sign-off decide.
ASI-02|A|lint, check|Hold|ASI02|Tool misuse: typed tools, allow-listed arguments, limits, and run, hold or refuse gates.
ASI-03|A|check|Deny|ASI03|Each agent has its own least-privilege identity; no shared credentials.
ASI-04|R|check|Deny|ASI04|Supply chain: pinned versions, signed manifests, SBOM, adapter trust classes, licence checks.
ASI-05|A|lint|Deny|ASI05|No model-written code runs; imported code is declared trusted and listed.
ASI-06|R|check|Hold|ASI06|Memory writes are typed, sourced and expiring; PHI in memory follows vault rules.
ASI-07|A|check|Deny|ASI07|Messages between agents are signed, schema-checked and gated.
ASI-08|A|check|Hold|ASI08|Circuit breakers, per-run budgets, and a hold after two consecutive failed checks.
ASI-09|O|check, eval|Hold|ASI09|Readings show their basis; rubber-stamp approvals are flagged.
ASI-10|R|check|Deny|ASI10|Signed records, baselines, a kill switch and replay catch a rogue agent."""),
 "gov.iso42001": ("ISO/IEC 42001 AI management system: evidence by Annex A domain",
   "iso42001", "ISO/IEC 42001:2023 (guidance; certification needs an accredited auditor)", "governance_reviewer", """
A-2|X|sign-off|Hold|Annex A.2|Policies related to AI, with owner and review date.
A-3|X|sign-off|Hold|Annex A.3|Internal organisation: roles and reporting lines from the compliance context.
A-4|R|lint|Hold|Annex A.4|Resources: inventory of models, data, tools and people from the agent card.
A-5|X|sign-off|Hold|Annex A.5|Impact assessment and its refresh dates.
A-6|R|check|Hold|Annex A.6|Life cycle: change records, replay results, pinned versions, release approvals.
A-7|R|check|Hold|Annex A.7|Data provenance, quality checks, PHI and consent labels.
A-8|R|check|Hold|Annex A.8|Information for interested parties: model cards, disclosures, incident channel.
A-9|R|check|Hold|Annex A.9|Use of AI: oversight records, hold and sign-off logs, intended-use checks.
A-10|R|check, sign-off|Hold|Annex A.10|Third parties: provider agreements, subprocessor lists, supplier reviews."""),
 "med.transparency": ("Transparency: AI disclosure, model cards and explanations",
   "transparency", "State AI disclosure laws, ONC HTI-1 DSI transparency, GDPR Art. 22", "clinical_safety_lead", """
TRN-01|O|lint, check|Deny|state law|Patient-facing generative output says AI produced it and how to reach a human.
TRN-02|O|check|Hold|ONC HTI-1|Clinician-facing readings show the model, version, inputs used and known limits.
TRN-03|X|sign-off|Hold|NIST AI RMF|A model card per profile records intended use, evaluation results and failure modes.
TRN-04|X|sign-off|Hold|45 CFR 170.315(b)(11)|Source attributes of predictive decision support interventions in listed health IT are stored with the card.
TRN-05|X|sign-off|Hold|164.520|Patients can learn AI was used in their care (links to PRV-19).
TRN-06|O|check|Hold|GDPR Art. 22|Significant automated decisions state their logic plainly and offer human review.
TRN-07|X|sign-off|Hold|Joint Commission and CHAI (guidance)|Staff and patients can report an AI incident through a documented channel."""),
 "soc2": ("SOC 2 Trust Services Criteria: evidence from Shio records (Shio does not certify)",
   "tsc", "AICPA Trust Services Criteria (2017, revised points of focus 2022); an audit by a qualified firm is required", "security_officer", """
CC-1|X|sign-off|Hold|CC1.1-CC1.5|Control environment: integrity and ethics, board oversight, structure, competence and accountability are attested.
CC-2|X|sign-off|Hold|CC2.1-CC2.3|Information and communication: internal and external communication of objectives and responsibilities.
CC-3|X|sign-off|Hold|CC3.1-CC3.4|Risk assessment: objectives, risks (the risk register), fraud risk and significant change are assessed.
CC-4|R|check|Hold|CC4.1-CC4.2|Monitoring activities: controls are evaluated and deficiencies reported (monitors, control evidence report).
CC-5|X|sign-off|Hold|CC5.1-CC5.3|Control activities are selected, developed and deployed through policies.
CC-6|P|check|Deny|CC6.1|Logical access: unique identities and least privilege for agents and callers.
CC-7|R|check|Deny|CC6.6-CC6.7|Transmission and boundary protection: TLS endpoints; data leaves only through the gate.
CC-8|R|check|Deny|CC6.8|Unauthorised or malicious software is prevented: pinned dependencies, signed manifests.
CC-9|R|check|Hold|CC7.1-CC7.2|System operations: anomalies and drift are detected and evaluated.
CC-10|R|check, sign-off|Hold|CC7.3-CC7.5|Incidents are evaluated, responded to and recovered from, as signed records.
CC-11|R|check|Deny|CC8.1|Change management: changes to models, prompts, tools and policies are authorised, tested and recorded.
CC-12|X|sign-off|Hold|CC9.1-CC9.2|Risk mitigation, including vendors and business partners.
A-1|X|sign-off|Hold|A1.1-A1.3|Availability: capacity, backup and recovery are planned and tested.
C-1|R|check|Deny|C1.1-C1.2|Confidentiality: confidential information is identified, protected and disposed of (vault, erasure).
PI-1|R|check|Deny|PI1.1-PI1.5|Processing integrity: inputs, processing and outputs are complete, accurate and recorded.
P-1|X|sign-off|Hold|P1-P8|Privacy: notice, choice, collection, use, access, disclosure, quality and monitoring are attested."""),
 "med.fairness": ("Fairness: Section 1557 decision support tools and subgroup performance",
   "fairness", "ACA Section 1557, 45 CFR 92.210", "clinical_safety_lead", """
FAI-01|R|lint, check|Hold|45 CFR 92.210(b)|An inventory of decision support uses of race, colour, national origin, sex, age or disability, from the agent card.
FAI-02|X|sign-off|Hold|45 CFR 92.210(c)|Reasonable efforts to mitigate discrimination risk are recorded.
FAI-03|P|lint|Deny|45 CFR 92.210|Protected-attribute inputs are declared per agent; undeclared use fails compile.
FAI-04|R|eval|Deny|45 CFR 92.210|Subgroup sensitivity, specificity and error rate meet the stated tolerance before deployment.
FAI-05|R|eval|Hold|45 CFR 92.201-205|Patient-facing output is tested in the languages and formats served.
FAI-06|R|eval|Hold|45 CFR 92.210|Proxy variables standing in for a protected class are flagged.
FAI-07|R|eval|Hold|45 CFR 92.210|Fairness results are re-run after each change."""),
}

README = """# {id}

{name}. Generated from the Shio policy pack specification (24 Nov 2026) by `tools/spec_packs.py`.

| | Controls |
|---|---|
| Enforced by the pre-model gate (`gate`) | {gate} |
| Proved statically (`lint`) | {lint} |
| Attested: a current signed attestation is required (`attestation`) | {attest} |
| Signed off by a person (`signoff`) | {signoff} |
| Planned: listed, not yet built | {planned} |

## Limits

Draft. Not reviewed by counsel{clin}; nothing in this pack is a compliance claim. Requirements are paraphrased from the
spec's summary of primary sources checked in November 2026 and must be re-read against the primary text before
review. Planned controls are not enforced: the coverage matrix (`shio preflight coverage`) shows them as not yet built.
Attestations prove that a named person signed that a duty was done, not that it was done well.
{extra}"""
EXTRA = {"reg.india": "\nThe pack runs in advisory mode (failures recorded, not enforced) until the DPDP Act's core duties are enforceable "
                      "(May 2027 on the published timeline), unless the compliance context lists it in `enforce_advisory`.\n",
         "med.sensitive": "\nThe state table ships with its schema and fixture rows only; counsel populates and reviews the rows for each "
                          "state the organisation operates in, and unreviewed states hold.\n"}


def proofs_for(pid, cid, stage, proof, on_fail, owner):
    key = f"{pid}:{cid}"
    if key in REGISTRY:
        return [{"kind": "gate", "control": cid}], "gate"
    if key in LINT:
        return [{"kind": "lint", "proof": LINT[key]}], "lint"
    if stage == "X" and "sign-off" in proof:
        return [{"kind": "attestation", "attestation": ATTEST_KIND.get(key, f"{pid}.{cid.lower()}"), "owner": owner,
                 "valid_days": VALID}], "attest"
    if proof.strip() == "sign-off":
        return [{"kind": "signoff", "role": owner}], "signoff"
    return [], "planned"


def build(pid):
    name, fw, fw_title, owner, rows = PACKS[pid]
    controls, counts = [], {"gate": 0, "lint": 0, "attest": 0, "signoff": 0, "planned": 0}
    for line in rows.strip().splitlines():
        cid, stage, proof, on_fail, cite, req = [x.strip() for x in line.split("|")]
        proofs, kind = proofs_for(pid, cid, stage, proof, on_fail, owner)
        counts[kind] += 1
        title = req.split(":")[0] if ":" in req[:40] else req.split(";")[0].split(",")[0]
        c = {"id": cid, "title": title[:90].rstrip("."), "requirement": req, "stage": stage,
             "on_fail": on_fail.lower(), "source": cite, "spec_proof": proof,
             "refs": [{"framework": fw, "ref": cite}]}
        if proofs:
            c["proof"] = proofs
        else:
            c["planned"] = True
        controls.append(c)
    pack = {"format": "shio-pack/1", "id": pid, "name": name, "version": "0.1.0", "effective": EFFECTIVE,
            "licence": "MIT OR Apache-2.0", "status": "draft",
            "review": {"counsel": None, **({"clinical_lead": None} if pid.startswith("med.") else {})},
            "description": f"{name}. From the Shio policy pack specification; draft, not reviewed.",
            "limits": "Draft and unreviewed. Planned controls are listed for coverage and not enforced.",
            "frameworks": [{"id": fw, "title": fw_title}],
            "advisory": pid == "reg.india", "controls": controls}
    out = ROOT / "shio" / "packs" / pid
    out.mkdir(parents=True, exist_ok=True)
    (out / "pack.json").write_text(json.dumps(pack, indent=1, ensure_ascii=False) + "\n")
    (out / "README.md").write_text(README.format(id=pid, name=name, clin=" or the clinical safety lead"
                                                 if pid.startswith("med.") else "", extra=EXTRA.get(pid, ""),
                                                 **counts))
    return pid, counts


if __name__ == "__main__":
    for pid in PACKS:
        p, c = build(pid)
        print(f"{p:20} " + "  ".join(f"{k} {v}" for k, v in c.items()))
