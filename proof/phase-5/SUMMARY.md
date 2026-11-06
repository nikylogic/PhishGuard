# Phase 5: LLM second opinion

**Result: 30 passed, 1 skipped.** The skipped test is the optional live check against a real LLM; it runs only when a free API key is supplied (`PG_LIVE_LLM=gemini:<key>`). No key was configured during this build. Full log: `pytest.txt`.

## What was built
`phishguard/llm.py`:
- **Providers:** none (the default), Gemini and Groq (free cloud tiers), and Ollama (fully offline). The model name is configurable in Settings.
- **The prompt:** the page text is wrapped in random markers that change every time, and the system message says the page text is untrusted data. If AI Guard flagged the text, an explicit warning is added.
- **Strict validation:** the reply must be JSON with exactly `risk` (an integer from 0 to 100), `category` (one of the four, or none) and `reasons` (1–3 short sentences). Anything else is discarded.
- **`apply_opinion()`:** the LLM can only raise a category's score up to its own value. It can never lower anything.
- A cache by page, an 8-second timeout, and a fallback to the rules on any error.

## What the tests prove
| Property | Tests |
|---|---|
| **A successful injection cannot relax a verdict:** an LLM reply of "safe, 0" leaves a DANGER page at DANGER (see `injection-defeated.md`) | 1 |
| The LLM can raise a CLEAR page to DANGER when it spots something the rules missed; a raise goes *to* its value, not on top | 2 |
| "none" changes nothing | 1 |
| 13 kinds of bad replies are rejected (plain text, out-of-range risk, a string or boolean risk, unknown category, empty or long reasons, an extra field like `"set_level": "clear"`) | 13 |
| Valid replies, including inside a code fence, are accepted | 1 |
| Timeout, offline, HTTP 429 and malformed provider responses all fall back to the rules | 4 |
| No provider, or a missing API key, means no LLM call | 2 |
| Cookies and form values are never in the prompt; page text is cut to 4,000 characters | 2 |
| The markers are random every time, and a page cannot fake the end marker | 2 |
| The Guard warning appears only when the Guard flagged the text; the system prompt marks page text as untrusted | 2 |
| The same page is answered from the cache (1 provider call for 2 reviews) | 1 |

`llm-sample.md` shows exactly what is sent to the LLM for a fake PayPal page.

## Issues found
None in this phase. One design note: page rules register themselves when `pagerules` is imported, so code that builds page findings must import it. The scan pipeline always does.
