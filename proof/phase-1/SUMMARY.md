# Phase 1: URL toolkit and URL rules

**Result: 101 / 101 tests passed.** Full log: `pytest.txt`. Benchmark: `bench.txt`.

## What was built
- `phishguard/urltools.py`
  - Cleans pasted links and refuses every non-web scheme (`javascript:`, `file:`, `ms-msdt:`, `search-ms:`, `data:` and others).
  - Parses domains offline with the bundled Public Suffix List.
  - Detects IP hosts, including the disguised forms `3232235777` and `0xC0A80001`, and private, loopback, link-local and cloud-metadata addresses.
  - Detects punycode and mixed alphabets, and maps lookalike letters back (Cyrillic "а" → Latin "a"; leetspeak "0" → "o", "rn" → "m").
  - Strips tracking parameters for the "clean link".
- `phishguard/intel.py`: a brand list (34 brands, each with its official domains), URL shorteners, risky TLDs, IP-logger domains and lure words.
- `phishguard/rules.py`
  - 19 URL rules in one weight table.
  - Scoring per category (phishing, malware, tracking, abuse), each capped at 100. The overall score is the highest category.
  - Levels: Clear (under 20), Caution (20–49), Danger (50 or more).

## What the tests prove
- 12 kinds of dangerous or broken input are refused, and 5 normalisation cases behave correctly.
- 7 domain-parsing cases and 14 private/public IP cases are correct.
- 50 real-world-style URLs each trigger exactly the right rules, with both positive and negative checks. These include `paypa1.com`, `rnicrosoft.com`, a Cyrillic lookalike of apple.com, `paypal.com.secure-check.net` and Grabify links, with no false alarms on google.com, wikipedia.org, onlinesbi.sbi, stream.com or telegraph.co.uk.
- Scoring caps, level boundaries, no double counting, and the clean link keeping real parameters.
- **Speed:** 1,000 URLs scored at an average of 0.30 ms each (target under 1 ms).

## Issues found and fixed during this phase
1. A test expected `0xC0A80001` to be 192.168.1.1. It is actually 192.168.0.1, so the test value was corrected; the code was right.
2. Bait words inside the website name itself (e.g. `hdfcbank-kyc.co`, `free-prize.zip`) were missed. The rule now reads the domain name too.
3. The first version averaged 0.83 ms per URL, close to the limit. Profiling showed the brand comparison repeated work for every brand. The lookalike letters are now mapped back once per URL and impossible matches are skipped by length, bringing it to 0.30 ms.
