# MIME extraction and shared input budget

`max_text_chars` retains its configuration name and accepted range (100–4000),
but now bounds **body characters plus retained URL-prefix characters together**.
Previously each of up to twelve URLs could add another 300 characters outside
the body budget. No configuration-file change is necessary.

Subject and displayed From remain separately capped at 200 characters each.
JSON field names, escaping, limitations and the system prompt add more input.
Character count is not token count and this change does not promise a particular
inference time or classification accuracy.

## Text

MIME transfer encodings are decoded according to declared headers. Undeclared
Base64 remains text; it is not guessed or interpreted as an attachment.
The original message is unchanged. The model's text representation collapses
whitespace, including nonbreaking spaces, before clipping. Zero-width spaces
become word boundaries. Standalone ZWNJ/ZWJ/BOM/word-joiner padding is removed;
join controls between letters, marks, numbers or symbols are preserved to avoid
blanket damage to languages and emoji sequences. Other format characters, such
as bidirectional controls, are not globally stripped.

Plain text is preferred when present. HTML extraction remains basic: script and
style content is excluded and block boundaries produce spaces. This is not a
browser renderer and does not resolve CSS visibility. `text_cleaned` indicates
that normalization changed the text, not that it is safe. `text_truncated`
compares the cleaned text with its allocated body budget.

## Links

HTML `a[href]` targets and HTTP(S) URLs in the chosen body are collected.
Stylesheet `link[href]` values are not included. URLs are collected before body
cleanup, so the cleaner does not silently rewrite their characters.

Exact duplicate targets are removed. Different paths and query strings are not
collapsed into a supposedly equivalent destination. Distinct authorities get
priority before repeated links from one authority. At most twelve targets are
retained. With a long body, approximately two thirds of the shared budget is
reserved for body text; a short body leaves more room for URLs. Unused URL
budget returns to the body.

URL characters are distributed across selected targets, with a maximum of 300
characters per target. Each retained prefix includes the complete authority,
including userinfo and port; targets that cannot fit that minimum are omitted.
Malformed targets are retained only if the whole target fits. Query parameters
are not removed by name and links are never fetched. A retained value can still
be an incomplete original prefix, not an executable or verified destination.

`urls_truncated` is true if any unique target is shortened or omitted.
`urls_omitted` counts omitted unique targets, not shortened ones. These flags
make missing evidence visible to the model; they do not restore it. Later parts
of a long redirect/query and omitted links may contain the decisive indicator.

## Metrics and verification

Successful CLI/bridge results include `input_text_chars`, `input_url_chars`,
`input_json_chars`, `urls_truncated` and `urls_omitted`, alongside existing model
load/prompt/generation timings and token counts when supplied by Ollama. The
bridge journal does not include the text, targets or model explanation.

After installing the patch, first extract a saved message without inference:

```python
from pathlib import Path
from aissa.analyzer import extract
sample = extract(Path('/path/to/sample.eml').read_bytes())
print(sample)
print(len(sample['text']) + sum(map(len, sample['urls'])))
```

That final count must not exceed the configured budget (default 1000). Compare
classification and token counts on the same real messages before enabling live
scoring. The budget reduces potential input size, not model mistakes or all
sources of latency. Real private messages/results should remain outside Git.
