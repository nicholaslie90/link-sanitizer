#!/usr/bin/env python3
"""Strip tracking junk from the URL on the clipboard, copy the clean one back.

usage:  sanitize            # clean whatever is on the clipboard
        sanitize <url>      # clean an argument instead
        sanitize --test     # run self-checks (offline)
"""
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Tracking params: matched by exact name or by prefix.
DROP_EXACT = {
    "fbclid", "gclid", "gclsrc", "dclid", "wbraid", "gbraid", "msclkid",
    "twclid", "ttclid", "yclid", "igshid", "igsh", "si", "mkt_tok",
    "_openstat", "_hsenc", "_hsmi", "vgo_ee", "__s", "oly_anon_id",
    "oly_enc_id", "mc_cid", "mc_eid", "ml_subscriber", "ml_subscriber_hash",
    "ck_subscriber_id", "s_kwcid", "spm", "scm", "share_id", "share_source",
    "shared_from", "ref", "ref_", "ref_src", "refsrc", "referrer", "cmpid",
    "campaign_id", "ad_id", "adset_id", "adgroupid", "campaignid", "creative",
    "placement", "keyword", "matchtype", "network", "device",
    "fb_action_ids", "fb_action_types", "fb_source", "fb_ref",
    "action_object_map", "action_type_map", "action_ref_map",
    "guccounter", "guce_referrer", "guce_referrer_sig", "trk", "trkCampaign",
    "sc_channel", "sc_campaign", "sc_content", "sc_medium", "sc_outcome",
    "cvid", "ocid", "icid", "ncid", "wt_zmc", "rss_id", "sourceid",
    "smid", "smtyp", "ito", "cmp", "taid", "curator", "__twitter_impression",
    "sref", "share", "shareid", "xtor", "at_recipient_id", "asgtbndr", "xmt",
}
DROP_PREFIX = ("utm_", "utm~", "ga_", "hsa_", "pk_", "piwik_", "matomo_",
               "vero_", "at_custom", "at_medium", "wickedid", "oly_")

# Hosts whose query string carries the real destination.
WRAPPERS = {
    "www.google.com", "google.com", "news.google.com",
    "l.facebook.com", "lm.facebook.com", "l.instagram.com",
    "l.messenger.com", "away.vk.com", "out.reddit.com",
    "steamcommunity.com", "www.youtube.com/redirect", "medium.com",
    "href.li", "www.linkedin.com", "linkedin.com",
    "*.safelinks.protection.outlook.com", "t.umblr.com", "vk.cc",
}
WRAPPER_KEYS = ("url", "u", "q", "z", "to", "target", "link", "dest", "r")

# Hosts that only ever redirect — worth one network round-trip to unwrap.
SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "rebrand.ly", "cutt.ly", "lnkd.in", "trib.al", "dlvr.it", "shorturl.at",
    "rb.gy", "tiny.cc", "s.id", "spoti.fi", "amzn.to", "a.co", "fb.me",
    "wp.me", "nyti.ms", "on.ft.com", "reut.rs", "econ.st", "bloom.bg",
    "apple.co", "msft.it", "tcrn.ch", "hubs.ly", "shar.es", "ift.tt",
}
# Share links on normal hosts: only this path prefix redirects.
SHORT_PATHS = {"www.threads.com": "/share/", "threads.com": "/share/",
               "www.threads.net": "/share/", "threads.net": "/share/"}

# Bare UA on purpose: a full browser UA gets a JS/HTML page instead of a 302
# from some hosts (Threads /share/), which leaves nothing to follow.
UA = "Mozilla/5.0"
# python.org builds ship without CA certs until "Install Certificates" is run;
# without this every HTTPS resolve fails and the link comes back unchanged.
_CA = "/etc/ssl/cert.pem"
SSL_CTX = ssl.create_default_context(
    cafile=None if os.path.exists(ssl.get_default_verify_paths().openssl_cafile)
    or not os.path.exists(_CA) else _CA)
AMAZON_ASIN = re.compile(r"/(?:dp|gp/product|gp/aw/d)/([A-Z0-9]{10})")


def _wrapper_match(host, path):
    if host in WRAPPERS:
        return True
    if host + path in WRAPPERS:
        return True
    # one wildcard form: *.safelinks.protection.outlook.com
    return host.endswith(".safelinks.protection.outlook.com")


def _clean_params(query):
    keep = []
    for k, v in parse_qsl(query, keep_blank_values=True):
        low = k.lower()
        if low in DROP_EXACT or low.startswith(DROP_PREFIX):
            continue
        keep.append((k, v))
    return urlencode(keep)


def _resolve(url, timeout=5.0):
    """Follow a shortener to its destination. Any failure -> original url."""
    for _ in range(5):
        parts = urlsplit(url)
        host = parts.hostname or ""
        if host not in SHORTENERS and not (
                host in SHORT_PATHS and parts.path.startswith(SHORT_PATHS[host])):
            return url
        # ponytail: GET, not HEAD — plenty of shorteners/CDNs 404 or 405 on
        # HEAD. We never read the body, so it costs one round-trip of headers.
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            # urllib follows redirects itself; .url is the final landing spot.
            with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
                nxt = r.url
        except urllib.error.HTTPError as e:
            nxt = e.url if e.url != url else (e.headers.get("Location") or "")
        except Exception:
            return url
        if not nxt.startswith(("http://", "https://")) or nxt == url:
            return url
        url = nxt
    return url


def sanitize(url, network=True):
    url = url.strip().strip("<>“”\"'")
    if not url.startswith(("http://", "https://")):
        return url  # not a web URL — hand it back untouched

    for _ in range(6):  # bounded: wrappers can nest
        if network:
            url = _resolve(url)
        s = urlsplit(url)
        host = (s.hostname or "").lower()

        if _wrapper_match(host, s.path):
            params = dict(parse_qsl(s.query, keep_blank_values=True))
            inner = next((params[k] for k in WRAPPER_KEYS
                          if params.get(k, "").startswith(("http://", "https://"))), None)
            if inner:
                url = inner
                continue

        if "amazon." in host:
            m = AMAZON_ASIN.search(s.path)
            if m:  # /dp/ASIN is the whole canonical link; query is all noise
                s = s._replace(path=f"/dp/{m.group(1)}", query="")

        frag = "" if s.fragment.startswith((":~:text=", "~:text=")) else s.fragment
        return urlunsplit((s.scheme, s.netloc, s.path,
                           _clean_params(s.query), frag))
    return url


def _test():
    c = lambda u: sanitize(u, network=False)
    assert c("https://x.com/a?utm_source=nl&utm_medium=e&id=7") == "https://x.com/a?id=7"
    assert c("https://x.com/a?fbclid=abc") == "https://x.com/a"
    assert c("https://youtu.be/dQw4?si=Xy&t=42") == "https://youtu.be/dQw4?t=42"
    assert c("https://www.google.com/url?q=https%3A%2F%2Fa.io%2Fb%3Fgclid%3D1&sa=U") \
        == "https://a.io/b"
    assert c("https://l.facebook.com/l.php?u=https%3A%2F%2Fa.io%2Fb&h=zz") == "https://a.io/b"
    assert c("https://www.amazon.com/Some-Long-Title/dp/B08N5WRWNW/ref=sr_1_3?keywords=x") \
        == "https://www.amazon.com/dp/B08N5WRWNW"
    assert c("https://x.com/a#section") == "https://x.com/a#section"
    assert c("https://x.com/a#:~:text=hi") == "https://x.com/a"
    assert c("not a url") == "not a url"
    assert c("https://x.com/a") == "https://x.com/a"
    assert c("https://www.threads.com/@u/post/Deg6?xmt=AQG0") == "https://www.threads.com/@u/post/Deg6"
    # nested wrapper: google -> facebook -> real
    assert c("https://www.google.com/url?q=https%3A%2F%2Fl.facebook.com%2Fl.php%3Fu%3Dhttps%253A%252F%252Fa.io%252Fb") \
        == "https://a.io/b"
    print("ok")


def main():
    if "--test" in sys.argv:
        return _test()
    raw = " ".join(sys.argv[1:]) or subprocess.run(
        ["pbpaste"], capture_output=True, text=True).stdout
    if not raw.strip():
        sys.exit("clipboard is empty")
    clean = sanitize(raw)
    subprocess.run(["pbcopy"], input=clean, text=True)
    print(clean)


if __name__ == "__main__":
    main()
