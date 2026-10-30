"""Extract every post by a given author from the scraped GhostTown forum."""
import glob
import re
import sys

AUTHOR = sys.argv[1] if len(sys.argv) > 1 else "mort1cia"

CARD = re.compile(r'(?is)<div class="post-card" id="[^"]*">(.*?)(?=<div class="post-card" id=|<div class="posts-list"|</div>\s*<div class="pagination)')
USER = re.compile(r'(?is)class="post-username"[^>]*>\s*([^<]+?)\s*<')
CONTENT = re.compile(r'(?is)class="post-content[^"]*"[^>]*>(.*?)</div>')


def strip_tags(h):
    h = re.sub(r"(?is)<br\s*/?>", "\n", h)
    h = re.sub(r"(?is)</p>", "\n", h)
    h = re.sub(r"(?s)<[^>]+>", "", h)
    h = (h.replace("&#39;", "'").replace("&amp;", "&").replace("&quot;", '"')
          .replace("&#x27;", "'").replace("&lt;", "<").replace("&gt;", ">")
          .replace("&#34;", '"'))
    h = re.sub(r"&[a-z0-9#]+;", " ", h)
    return re.sub(r"[ \t]+", " ", h).strip()


posts = []
for f in sorted(glob.glob("topics_html/*.html")):
    h = open(f, encoding="utf-8", errors="replace").read()
    h = re.sub(r"(?is)<style.*?</style>", "", h)
    for card in CARD.findall(h):
        mu = USER.search(card)
        mc = CONTENT.search(card)
        if not mu or not mc:
            continue
        if mu.group(1).strip() != AUTHOR:
            continue
        body = strip_tags(mc.group(1))
        if body:
            # topic slug from the filename for context
            slug = f.split("/")[-1].replace(".html", "")
            posts.append((slug, body))

print(f"=== {len(posts)} posts by {AUTHOR} ===\n")
slug = None
for s, b in posts:
    if s != slug:
        slug = s
        print(f"\n--- {s} ---")
    print(f"  * {b}")
print()
