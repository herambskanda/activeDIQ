---
title: <Job, as an imperative: "Bulk-create users from CSV">
kind: how-to
audience: admin
applies_to: ">=<version>"
verified_on: <version or sha> YYYY-MM-DD
spec: knowledge/product/specs/<feature>.md
---

# <Bulk-create users from CSV>

<One or two sentences: what you achieve and when you would do this.>

## Before you start

- **activeDIQ role:** <role> with scope over the target OU.
- **AD rights used by activeDIQ:** <e.g. Create User objects on the target OU> (see
  [Permissions reference](../reference/permissions.md)).
- **You need:** <a CSV in the format described in [CSV columns](../reference/csv-user-columns.md)>.

## Steps

1. Go to **Users** and select **Import from CSV**.

   ![The Users page with Import from CSV highlighted](../../_media/<page-slug>/01-import-button.png)

2. Select your file and choose the target OU.
3. Select **Run dry run**.

   activeDIQ checks every row against the domain: name length, uniqueness and the password
   policy that applies. Rows with problems are listed with the column and the reason.

4. Review the impact preview, then select **Create 48 users**.

   > **Warning:** <what is irreversible, if anything, and how to check before continuing.>

## Check the result

<How the admin verifies success: the results page, the audit entry, a filter that shows the new
objects.>

## If something goes wrong

| You see | Why | What to do |
| --- | --- | --- |
| <message as shown on screen> | | |

## Related

- Explanation: <how it works page>
- Reference: <columns, permissions, API equivalent>
- PowerShell: `<Verb-AdiqNoun>` <!-- cmdlet naming provisional until the api-design contract -->
