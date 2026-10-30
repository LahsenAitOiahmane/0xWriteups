# Handoff prompt — DEADFACE CTF 2026, "You Wouldn't Git It" (125 pts, OSINT + Web)

Paste the block below into the next agent. It is self-contained.

---

## CONTEXT

I am playing DEADFACE CTF 2026 (ctf.deadface.io, runs Oct 17–18, 2026). I need help solving one
challenge. Two challenge cards are relevant because the second is a direct continuation of the first.

**Challenge A (already solved, gives you the seed artifacts):**
- Title: "The Vibes Are Freaking Me Out" — 75 pts, OSINT, author Cyb0rgSw0rd
- Text: "We've received intelligence that a DEADFACE operative may have been using AI to create a browser
  extension that would enable them to communicate openly outside of the GhostTown forums using a new model
  called Maude. We need to find the tool they've built so we can find out what they're trying to hide from us."
- Solution already known: the tool is the GitHub repo `fr34ked0ut/HIPS` (browser extension "Hidden In Plain
  Sight", built by GhostTown user b1tfr34k, who stole it from the original author "Cyb0rg"; its `.maude/`
  directory shows it was written with an AI assistant called Maude). The flag was a "crew token" in
  `.maude/skills/payload-gen/SKILL.md`, base64-encoded then reversed:
  `fSEzcjNodzBOXzNNX3N0M0dfZ24xdHBtMHJQX3MxaFRfMTFBe2VjYWZkYWVk`
  → base64-decode → reverse → `deadface{A11_Th1s_Pr0mpt1ng_G3ts_M3_N0wh3r3!}` (validated, belongs to A).

**Challenge B (the one I need solved):**
- Title: "You Wouldn't Git It" — 125 pts, OSINT + Web, author Cyb0rgSw0rd
- Text: "Everybody wants to be a content creator these days, but nobody wants to create good content. I'm
  not even sure how they get paid to do this stuff, really... When I go on social media all I want to do is
  doom scroll until I fall asleep. Maybe I just don't get the memes anymore because I don't laugh at any
  of these."
- Card notes: "this challenge is a continuation of The Vibes Are Freaking Me Out. Use context and artifacts
  found in that challenge." Flag format: `deadface{flag-text}`; there are two hints (#1 costs 5 points,
  #2 costs 0 points) that I have NOT yet read — if I provide them, use them first.

## THE FALSE STARTS — ALREADY EXHAUSTED, DO NOT REDO

1. `fr34ked0ut/HIPS`: full git history (19 commits), `git fsck --lost-found` clean, no dangling objects,
   refs, stash, or notes. Only two networks/domains referenced: a dead Discord webhook (API returns
   "Unknown Webhook") and `updates.kfqyy3af.net` (NXDOMAIN). All `.env` secrets are decoys.
2. `fr34ked0ut/SecondBrainTrain` + full history — decoy repo with a fake `HF_TOKEN`.
3. fr34ked0ut's 4 forks, followers, following, events, sponsors — nothing.
4. Every one of the 14 GhostTown usernames tested on GitHub: 9 exist but they are real unrelated accounts
   (created 2009–2022, real OSS content). No 2026 puzzle account for any persona.
5. No GitHub account exists for "Cyb0rgSw0rd" / the original extension author (searched `cyb0rg*` users and
   `stego`/`unicode`/`hidden in plain sight` repos). Note `mirveal-deadface` on GitHub is a 2025 challenge
   account, not ours.
6. "DoomScroll" (the in-universe social platform) is named exactly once in GhostTown thread 48. `doomscroll.io`
   is a parked domain, `doomscroll.com` is an unrelated film site, no deadface.io subdomain exists.
7. The CDN bucket `deadface.sfo3.cdn.digitaloceanspaces.com` returns **403 (not 404) for non-existent keys**,
   so status codes cannot confirm guesses. Only two public objects: `/2026/img/IMG007.png` and
   `/2026/challenges/brainscan/emedrabox.png`.
8. TLS certs on all live hosts (ghosttown/support/shop/ctf/deadface.io/oathnet.org) are clean.
9. No exposed `.git/` directory on any live host.
10. Alice's blog at `https://170.187.156.131:8443/` (member login, unicorn cert with
    `Deadface{c@tch_m3_if_y0u_c@n}`) belongs to a different (geolocation) challenge.
11. `oathnet.org` ("Exposure Intelligence", checks emails/usernames/domains) is a live service but requires
    login; no unauthenticated API endpoint found.
12. `hostbusters.io` is unreachable.
13. GhostTown itself is a separate challenge; its forum content (threads, 23 meme images) is story/other
    challenges, and I scanned all threads for Unicode steganography — only thread 37 has zero-width bits.

## USEFUL FACTS YOU CAN BUILD ON

- Live hosts under deadface.io: `ghosttown`, `support` (osTicket), `shop` (Cyber Hacktics Shopify merch),
  `ctf` (CTFd). Only `/api/v1/notifications` on the CTFd is unauthenticated; challenges/scoreboard/hints
  all 302 to /login.
- The CTFd notifications publicly mention: Hostbusters and Database challenges were restarted, a "Hidden
  Loot Box" flag was corrected, one video challenge's flag is in the Challenge Card, Wave 2 released, and
  teams using AI or sharing accounts get banned (keep that in mind about how you use any AI help).
- HIPS manifest says `gecko.id = unicode-stego-kit@deadface.io`; original app title "Cyb0rg's Unicode
  Steganography Kit". The tool's whole purpose: hide messages in Unicode so they can be posted in the open
  (e.g., on social media) without looking like anything.
- Local artifacts from my session are on my machine under `%TEMP%\df26\` (`C:\Users\sadik\AppData\Local\Temp\df26\`):
  `HIPS/` (full clone), `SBT/` (SecondBrainTrain clone), `memes/` (23 forum images), `th/*.html` +
  `th2_*.html` (all GhostTown threads, all pages), `render.py` (HTML→text helper), `IMG007.png`.

## LEADING HYPOTHESIS (rank my guess, verify or discard)

"How they get paid" + "content creator" + "social media" + the git pun in the title suggest a **monetized
persona account** (GitHub Sponsors / Ko-fi / Patreon / a blog with donations) belonging to a GhostTown
character, or a repo on a **different** Git host (GitLab/Bitbucket/Codeberg) used by the persona. The seed
handle should come from the Vibes artifacts — most likely the original author "Cyb0rg" (challenge author's
handle is `Cyb0rgSw0rd`, and the GhostTown thread 37 story says b1tfr34k stole his kit), or the AI "Maude".

Things I could NOT do because the challenge card is behind a login wall:
- read the two hints, read the card's links/attachments, or see any starting handle/URL.

If I send you the hint text or the card contents, prioritize those.

## WORKING STYLE I NEED

- Give me concrete, runnable commands and exact paths, not theory.
- I am on Windows with Git Bash; the sandbox forces all traffic through an HTTP proxy on 127.0.0.1 (read
  the port from `$http_proxy` at runtime). Some hosts are blocked outright (curl exit 000/502).
- Windows Python cannot read `/tmp`; write scratch files to `%TEMP%\...` and pass real Windows paths.
- GitHub's unauthenticated API is 60 requests/hour — prefer `git clone` over API calls when mining history.
- Flag format: `deadface{...}`.
