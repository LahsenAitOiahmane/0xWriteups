import glob, re, html
for f in sorted(glob.glob('topics_html/*.html')) + sorted(glob.glob('cat_*.html')):
    h = open(f, encoding='utf-8', errors='replace').read()
    h = re.sub(r'(?is)<style.*?</style>', '', h)
    h = re.sub(r'(?is)<script.*?</script>', '', h)
    for m in re.finditer(r'(?is)<div class="post-card" id="[^"]*">(.*?)(?=<div class="post-card" id=|</div>\s*<div class="posts-list)', h):
        blk = m.group(1)
        u = re.search(r'(?is)class="post-username"[^>]*>\s*([^<]+?)\s*<', blk)
        c = re.search(r'(?is)class="post-content[^"]*"[^>]*>(.*?)</div>', blk)
        if not u or not c: continue
        user = u.group(1).strip()
        txt = re.sub(r'(?s)<[^>]+>', ' ', c.group(1))
        txt = html.unescape(re.sub(r'\s+', ' ', txt)).strip()
        if not txt: continue
        if re.search(r'(?i)\b(password|passwd|pw\b|creds?|reuse|same (?:one|pw|login)|always use|i just use|my login|since 20\d\d|birthday|mused|reuse)', txt):
            print(f'[{f.split("/")[-1][:34]:34}] {user:12} {txt[:200]}')
