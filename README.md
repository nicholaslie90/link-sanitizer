# link-sanitizer

Paste-and-go URL cleaner for macOS. Reads the clipboard, strips tracking, copies the clean URL back.

```
$ sanitize
https://www.nytimes.com/2024/01/01/tech/ai.html      # also on your clipboard

$ sanitize "https://x.com/a?utm_source=nl&fbclid=z"  # or pass it directly
https://x.com/a
```

## What it removes

- **Tracking params** — `utm_*`, `fbclid`, `gclid`, `msclkid`, `igshid`, `si`, `mkt_tok`, `smid`, `ref`, ~90 more by exact name or prefix.
- **Redirect wrappers** — unwraps `google.com/url?q=`, `l.facebook.com/l.php?u=`, Outlook safelinks, LinkedIn, etc. Nested wrappers unwrap recursively (bounded at 6).
- **Short links** — resolves `bit.ly`, `t.co`, `lnkd.in`, `amzn.to`, … to the real destination, then cleans that. Only these known hosts trigger a network call; everything else is offline string surgery.
- **Amazon noise** — `/Some-Title/dp/B08N5WRWNW/ref=sr_1_3?keywords=…` → `/dp/B08N5WRWNW`.
- **Text fragments** — `#:~:text=…`. Ordinary `#anchors` are kept.

Anything that isn't an `http(s)` URL is returned untouched. Any network failure falls back to the input unchanged, so you never lose a link.

## Install

```sh
ln -sf "$PWD/sanitize.py" ~/.local/bin/sanitize
```

## Test

```sh
python3 sanitize.py --test
```

Stdlib only, no dependencies.
