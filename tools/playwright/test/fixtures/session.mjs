// A minimal record spec used by tools.test.mjs.
export default async function ({ page, baseURL }) {
  await page.goto(baseURL);
  await page.getByRole('button', { name: 'Go' }).click();
  await page.getByText('clicked').waitFor();
  await page.waitForTimeout(600); // give the video a few frames
}
