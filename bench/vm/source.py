#!/usr/bin/env python3
"""source.py PORT: on the server VM, a TCP server that sends zeros to every connection for as long as it is taken."""
import asyncio, sys

CHUNK = b"\0" * 65536


async def handle(_r, w):
    try:
        while True:
            w.write(CHUNK)
            await w.drain()
    except Exception:
        pass
    finally:
        w.close()


async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", int(sys.argv[1]))
    await srv.serve_forever()


asyncio.run(main())
