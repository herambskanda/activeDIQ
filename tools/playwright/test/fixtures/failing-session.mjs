export default async function ({ page, baseURL }) {
  await page.goto(baseURL);
  await page.getByRole('button', { name: 'does-not-exist' }).click({ timeout: 500 });
}
