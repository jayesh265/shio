"""A SYNTHETIC fixture world for the gate: a fictional clinic ("Northwind Community Clinic"), its compliance context,
three model profiles, registries and attestations. Every control's fixtures run against it, the mutation tests use
it, and `shio preflight demo` prints decisions over it. None of it describes a real organisation or provider."""
import copy
import datetime as dt

TODAY = dt.date(2026, 11, 24)

CONTEXT = {
    "organisation": "Northwind Community Clinic (fictional)",
    "hipaa_role": "covered entity",
    "purposes": ["treatment", "payment", "operations", "research", "marketing"],
    "jurisdictions": ["US", "US-CA"],
    "data_classes": ["phi", "part2", "psychotherapy", "genetic", "minors", "reproductive", "trial"],
    "device_status": "not a device",
    "risk_tier": "high",
    "retention": {"decision_record": 2190, "prompt": 30},
    "responsible_roles": {"privacy_officer": "P. Okafor", "security_officer": "L. Brandt",
                          "clinical_safety_lead": "Dr A. Mensah", "irb_liaison": "R. Iyer"},
}


def _agreement(kind, scope, start="2026-01-01", expiry="2027-12-31", ref=None):
    return {"kind": kind, "reference": ref or f"{kind.upper()}-001", "signatory": "Vendor Legal (fictional)",
            "scope": scope, "start": start, "expiry": expiry}


MODELS = {"models": {
    "clinical-llm": {"endpoint": "https://llm.vendor-a.example/v1", "version": "2026-10-01", "service": "Vendor A Health API",
                     "region": "US", "retention_days": 0, "logging": "no content logging", "training_on_inputs": False,
                     "allowed_classes": ["phi", "unlabelled", "trial", "minors", "genetic", "reproductive", "part2"],
                     "agreements": [_agreement("baa", ["Vendor A Health API"])],
                     "subprocessors": [{"name": "Vendor A Cloud", "agreement": _agreement("baa", ["Vendor A Health API"],
                                                                                         ref="BAA-SUB-1")}],
                     "preference": 10},
    "general-llm": {"endpoint": "https://api.vendor-b.example/v2", "version": "b-7", "service": "Vendor B Chat",
                    "region": "US", "retention_days": 30, "logging": "30-day abuse monitoring",
                    "training_on_inputs": False, "allowed_classes": [], "agreements": [], "preference": 50},
    "eu-llm": {"endpoint": "https://eu.vendor-c.example/v1", "version": "c-3", "service": "Vendor C EU",
               "region": "EU", "retention_days": 0, "logging": "none", "training_on_inputs": False,
               "allowed_classes": ["phi", "unlabelled"],
               "agreements": [_agreement("baa", ["Vendor C EU"]), _agreement("dpa", ["Vendor C EU"])],
               "preference": 90},
}}

REGISTRIES = {
    "purposes": {
        "treatment": {"fields": ["reason", "history", "medications", "allergies", "results", "note", "age"],
                      "needs_phi": True},
        "payment": {"fields": ["claim", "codes", "amount"], "needs_phi": True},
        "operations": {"fields": ["metric", "site", "count"], "needs_phi": False},
        "research": {"fields": ["age", "results", "diagnosis", "note"], "needs_phi": True},
        "marketing": {"fields": ["campaign"], "needs_phi": False},
    },
    "authorization_required": ["marketing"],
    "authorizations": {
        "AUTH-1": {"subject": "P-100", "purpose": "marketing", "recipient": "clinical-llm", "information": "visit summary",
                   "signed": True, "dated": "2026-06-01", "expiry": "2027-06-01", "revocation_statement": True,
                   "revoked": False},
    },
    "roles": {"clinician": ["clinical", "medications", "results", "demographics"],
              "billing": ["billing", "demographics"], "analyst": ["aggregate"]},
    "field_categories": {"reason": "clinical", "history": "clinical", "note": "clinical", "medications": "medications",
                         "allergies": "medications", "results": "results", "age": "demographics", "claim": "billing",
                         "codes": "billing", "amount": "billing", "metric": "aggregate", "site": "aggregate",
                         "count": "aggregate", "diagnosis": "clinical", "campaign": "aggregate"},
    "shared_accounts": ["service", "admin", "shared", "root"],
    "public_fields": ["metric", "site", "count", "campaign"],
    "restrictions": {"P-200": {"purposes": ["operations"], "destinations": []}},
    "opt_outs": {"P-300": ["marketing"]},
    "field_classes": {"sud_note": "part2", "therapy_note": "psychotherapy", "genotype": "genetic"},
    "part2_consents": {"P-400": {"purposes": ["treatment"], "revoked": False}},
    "minors": {"P-500": {"age": 15, "state": "US-CA", "consent_ok": False}},
    "state_table": {"US-CA": {"reproductive": "shield", "genetic": "CalGINA", "minors": "minor may consent to some care",
                              "reviewed": "2026-09-01", "statute": "fictional fixture row"}},
    "studies": {"ST-1": {"protocol_version": "3", "irb_expiry": "2027-03-01", "pi": "Dr N. Haddad",
                         "fields": ["age", "results", "diagnosis"], "consent_version": "3",
                         "consents": {"P-600": "3", "P-601": "2"}, "withdrawn": ["P-602"]},
                "ST-OLD": {"protocol_version": "1", "irb_expiry": "2026-01-31", "pi": "Dr N. Haddad",
                           "fields": ["age"], "consent_version": "1", "consents": {}, "withdrawn": []}},
    "research_pathways": {"authorization": "AUTH", "waiver": "WAIVER", "preparatory": "PREP",
                          "decedents": "DECEDENT", "limited data set": "DUA", "de-identified": "DEID"},
    "waivers": {"ST-1": {"board": "Northwind IRB (fictional)", "approved": "2026-02-01", "criteria_met": True}},
    "data_use_agreements": {"clinical-llm": {"expiry": "2027-12-31"}},
    "eu_transfer_mechanisms": {"general-llm": "scc"},
    "india_consents": {"P-700": ["treatment"]},
    "india_restricted_regions": ["XR"],
}

ATTESTATIONS = [("security-risk-analysis", "security_officer", "L. Brandt", "2026-02-01", "2027-02-01"),
                ("privacy-program", "privacy_officer", "P. Okafor", "2026-01-15", "2027-01-15"),
                ("baa-terms-reviewed", "privacy_officer", "P. Okafor", "2026-01-15", "2027-01-15")]


def world(context=None, models=None, registries=None):
    """Deep copies of the fixture world's three files, optionally edited by functions that take the dict."""
    c, m, r = copy.deepcopy(CONTEXT), copy.deepcopy(MODELS), copy.deepcopy(REGISTRIES)
    for fn, d in ((context, c), (models, m), (registries, r)):
        if fn:
            fn(d)
    return c, m, r
