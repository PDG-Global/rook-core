import asyncio, websockets
async def echo(ws):
    async for m in ws: await ws.send(m)
async def main():
    async with websockets.serve(echo, "127.0.0.1", 9001): await asyncio.Future()
asyncio.run(main())
