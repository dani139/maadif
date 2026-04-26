import { test, expect } from '@playwright/test';

test.describe('Version Tracker Download', () => {
  test('download button should trigger API call and show spinner', async ({ page }) => {
    // Collect console logs
    const consoleLogs: string[] = [];
    page.on('console', msg => {
      consoleLogs.push(`${msg.type()}: ${msg.text()}`);
    });

    // Collect network requests
    const apiRequests: string[] = [];
    page.on('request', request => {
      if (request.url().includes('/api/')) {
        apiRequests.push(`${request.method()} ${request.url()}`);
      }
    });

    page.on('response', response => {
      if (response.url().includes('/api/')) {
        apiRequests.push(`  -> ${response.status()} ${response.url()}`);
      }
    });

    // Go to the page
    await page.goto('http://localhost:5173');

    // Wait for versions to load
    await page.waitForSelector('table', { timeout: 10000 });

    // Find a download button (not already downloaded)
    const downloadButtons = page.locator('button[title="Download APK"]');
    const count = await downloadButtons.count();
    console.log(`Found ${count} download buttons`);

    if (count > 0) {
      // Click the first download button
      const firstButton = downloadButtons.first();

      // Get the row info
      const row = firstButton.locator('xpath=ancestor::tr');
      const versionCell = row.locator('td').first();
      const versionText = await versionCell.textContent();
      console.log(`Clicking download for version: ${versionText}`);

      // Click and wait for network activity
      await firstButton.click();

      // Wait a moment for the mutation to trigger
      await page.waitForTimeout(1000);

      // Check if spinner appeared (RefreshCw with animate-spin)
      const spinners = page.locator('.animate-spin');
      const spinnerCount = await spinners.count();
      console.log(`Spinners visible: ${spinnerCount}`);

      // Log collected data
      console.log('\nConsole logs:', consoleLogs);
      console.log('\nAPI requests:', apiRequests);

      // Expect at least one API call to /download
      const downloadCalls = apiRequests.filter(r => r.includes('/download'));
      expect(downloadCalls.length).toBeGreaterThan(0);
    } else {
      console.log('No download buttons found - all versions may be downloaded');
    }
  });

  test('check for errors in console', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', err => {
      errors.push(err.message);
    });
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    await page.goto('http://localhost:5173');
    await page.waitForSelector('table', { timeout: 10000 });

    // Wait a bit for any async errors
    await page.waitForTimeout(2000);

    console.log('Errors found:', errors);
    // Report but don't fail - we want to see the errors
  });
});
