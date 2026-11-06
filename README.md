# databricks-certifi-scan

A Databricks notebook (source format) that finds certifi pins and copied certifi packages that block certifi 2026.10.19+ (the eMudhra CA removal) across one or more workspaces.

It covers:

1. Workspace inventory: apps, custom model serving, custom container images
2. Restart list: running clusters older than a threshold (default 24h)
3. certifi scan: notebooks, workspace files, jobs, apps, cluster libraries, init scripts, model serving, UC Python UDFs and (optionally) volumes

Everything is read-only and results are only displayed. The optional test fixtures cell writes a small folder to your home directory and is off by default.

## Usage

Import `certifi_emudhra_scan.py` into a workspace (Workspace > Import) and run it.

- `scan_mode = current`: scans the current workspace with your own login
- `scan_mode = urls`: scans a comma separated list of workspace URLs with a service principal
- `scan_mode = account`: scans every running workspace in the account with a service principal that is an account admin and a workspace admin everywhere

For `urls` and `account`, put the service principal's OAuth credentials in a secret scope as `sp-client-id` and `sp-client-secret`.

Findings are tagged ACTION (pin or old copy blocks 2026.10.19+), REVIEW (needs a manual look) or REDEPLOY (apps).

Provided as is, with no warranty. This is not an official Databricks tool.
