import { test, expect } from '@playwright/test';

test('debug version tracker', async ({ page }) => {
  await page.goto('http://localhost:5173');

  // Wait for page to load
  await page.waitForTimeout(1000);

  // Click on Version Tracker in sidebar
  const versionTrackerLink = page.locator('text=Version Tracker');
  await versionTrackerLink.click();

  // Wait for table to appear
  await page.waitForSelector('table', { timeout: 10000 });
  await page.waitForTimeout(500);

  // Get page HTML for the table
  const tableHtml = await page.locator('table').innerHTML();
  console.log('Table HTML (first 3000 chars):');
  console.log(tableHtml.substring(0, 3000));

  // Get all buttons with Download title
  const downloadBtns = page.locator('button[title="Download APK"]');
  const downloadCount = await downloadBtns.count();
  console.log(`\nDownload buttons: ${downloadCount}`);

  // Check for emerald checkmarks (downloaded status)
  const checkmarks = page.locator('.text-emerald-500');
  const checkCount = await checkmarks.count();
  console.log(`Emerald checkmarks (downloaded): ${checkCount}`);

  // Take a screenshot
  await page.screenshot({ path: 'test-results/version-tracker.png', fullPage: true });
  console.log('\nScreenshot saved to test-results/version-tracker.png');
});

test('click download button', async ({ page }) => {
  // Collect console logs
  const logs: string[] = [];
  page.on('console', msg => logs.push(`[${msg.type()}] ${msg.text()}`));

  // Collect network requests
  const requests: string[] = [];
  page.on('request', req => {
    if (req.url().includes('/api/')) {
      requests.push(`-> ${req.method()} ${req.url()}`);
    }
  });
  page.on('response', res => {
    if (res.url().includes('/api/')) {
      requests.push(`<- ${res.status()} ${res.url()}`);
    }
  });

  await page.goto('http://localhost:5173');

  // Navigate to Version Tracker
  await page.locator('text=Version Tracker').click();
  await page.waitForSelector('table', { timeout: 10000 });
  await page.waitForTimeout(500);

  // Find download buttons
  const downloadBtns = page.locator('button[title="Download APK"]');
  const count = await downloadBtns.count();
  console.log(`Found ${count} download buttons`);

  if (count > 0) {
    // Click first download button
    console.log('Clicking first download button...');
    await downloadBtns.first().click();

    // Wait for API call
    await page.waitForTimeout(3000);

    console.log('\nNetwork requests:');
    requests.forEach(r => console.log('  ' + r));

    console.log('\nConsole logs:');
    logs.forEach(l => console.log('  ' + l));

    // Check for spinner
    const spinners = page.locator('.animate-spin');
    const spinnerCount = await spinners.count();
    console.log(`\nSpinners visible: ${spinnerCount}`);
  } else {
    console.log('No download buttons found - checking why...');

    // Get row data
    const rows = page.locator('tbody tr');
    const rowCount = await rows.count();
    console.log(`Found ${rowCount} rows`);
  }

  // Screenshot
  await page.screenshot({ path: 'test-results/after-click.png', fullPage: true });
});
