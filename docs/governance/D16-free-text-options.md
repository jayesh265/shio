# D16: Free-text output, the three-option ladder, and measured rates

Free text can't be fully checked. Generate-then-verify (`shio/governance/gtv.py`) checks generated text sentence by
sentence against its source; the team then picks, **per use**, how much free text to allow:

| Option | What is shown | A sentence or claim that can't be verified |
|---|---|---|
| 1. Structured only | only claims, each with its quote from the source | the claim is dropped |
| 2. Verify and drop | free text, minus unsupported sentences (and a note saying how many) | the sentence is removed |
| 3. Verify and reject | free text, all or nothing | the whole text goes to a person |

A sentence is supported when every figure in it appears in the source (value and unit) and at least 75% of its content
words do. That is a heuristic, which is why the rates below are measured, not assumed.

## Measured rates

From `examples/medical/referral/results/gtv.json`, written by `python measure_gtv.py` in that folder: 24 cases built
from the 8 synthetic referral letters (for each letter, a faithful text, a paraphrased but correct text, and a text with
a wrong figure and an invented treatment), labelled per sentence and per claim.

| Option | Good units | Wrongful rejection of good text | Bad units | Bad let through |
|---|---|---|---|---|
| 1. Structured only (claims) | 56 | **14.3%** | 16 | 0% |
| 2. Verify and drop (sentences) | 64 | **34.4%** | 16 | 0% |
| 3. Verify and reject (whole texts) | 16 | **68.8%** | 8 | 0% |

**Limits of these numbers.** The letters, texts and labels are synthetic and written by engineers; the paraphrases
were written to stress the checks. The numbers show the trade-off's shape (on this set, nothing bad gets through any
option, and the more free text an option keeps, the more good text it wrongly withholds) but they are not evidence about
a real model or real letters. Rates for a decision must come from a set the clinical safety lead has labelled.

## Decision: option per use (to be made by the team)

Until rates are measured on a clinician-labelled set, the build plan's risk mitigation applies: clinician sign-off on
anything patient-facing. The referral summariser (reference agent 1) uses option 1 (structured claims with quotes) and
every summary needs a clinician's sign-off.

| Use | Option | Decided by | Date |
|---|---|---|---|
| Referral summary for the receiving clinician | 1 (proposed) | | |
| | | | |
