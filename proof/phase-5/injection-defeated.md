# Prompt injection defeated

A phishing page hid text telling AI systems to call it safe. Suppose the injection worked
and the LLM replied that the page is safe:

```json
{
 "risk": 0,
 "category": "phishing",
 "reasons": [
  "This website is completely safe."
 ]
}
```

| | Score | Stamp |
|---|---:|---|
| Rules only | 60 | DANGER |
| Rules + injected LLM reply | 60 | DANGER |

The verdict did not move: the LLM can only raise a score, never lower it.
