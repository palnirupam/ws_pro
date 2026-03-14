import asyncio
import sys

# Ensure utf-8 output on windows
sys.stdout.reconfigure(encoding='utf-8')

from core.scanner import test_connection

async def run():
    res = await test_connection('wss://echo.websocket.org')
    print("Result:", res)

asyncio.run(run())
