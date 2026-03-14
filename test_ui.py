import asyncio
from playwright.async_api import async_playwright
import time

async def test_interceptor():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        print("1. Navigating to Dashboard...")
        await page.goto("http://localhost:5000", wait_until="networkidle")
        
        print("2. Clicking Interceptor setup...")
        # Check "Interceptor" box in options
        await page.click("label:has-text('Interceptor')")
        
        # Click the top tab
        await page.click("text='Interceptor'")
        
        print("3. Entering WS URL and starting proxy...")
        # Use specific selectors based on dashboard HTML
        await page.fill("input[placeholder='ws://localhost:8765']", "ws://localhost:8765")
        await page.click("text='▶ Start Proxy'")
        
        print("4. Waiting 5s for messages...")
        await page.wait_for_timeout(5000)
        
        # Check counters
        msgs = await page.evaluate("document.getElementById('int-total')?.textContent || '0'")
        print(f"Message count after 5s: {msgs}")
        
        print("5. Testing Search...")
        await page.fill("#int-search", "type")
        await page.wait_for_timeout(1000)
        
        print("6. Testing Clear...")
        await page.click("button:has-text('Clear')")
        await page.wait_for_timeout(1000)
        msgs_cleared = await page.evaluate("document.getElementById('int-total')?.textContent || '0'")
        print(f"Message count after Clear: {msgs_cleared}")
        
        # Export testing
        print("7. Testing Export download...")
        async with page.expect_download() as download_info:
            await page.click("button:has-text('Export')")
        download = await download_info.value
        print(f"Exported to: {download.suggested_filename}")
        
        await browser.close()
        print("All Tests Complete!")

asyncio.run(test_interceptor())
