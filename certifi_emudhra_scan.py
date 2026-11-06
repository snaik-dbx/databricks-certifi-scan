# Databricks notebook source
# MAGIC %md
# MAGIC # certifi / eMudhra scan (CVE-2026-111943)
# MAGIC
# MAGIC Three scripts:
# MAGIC
# MAGIC 1. **Workspace inventory**: which workspaces have apps, model serving and custom container images (the checklist)
# MAGIC 2. **Restart list**: clusters running longer than 24 hours
# MAGIC 3. **certifi scan**: pins below 2026.10.19 and copies of certifi in code, jobs, apps, cluster libraries, model serving, UC Python UDFs and volumes
# MAGIC
# MAGIC Everything is read-only and results are only displayed. The one exception is the optional test fixtures cell, which is off by default.
# MAGIC
# MAGIC **Testing on a single workspace (fevm):** leave `scan_mode = current`. This uses your own notebook login, so no service principal is needed.
# MAGIC **Customer run:** set `scan_mode = account` and fill in the account ID and secret scope for a service principal that is an account admin and a workspace admin everywhere.

# COMMAND ----------

%pip install -U databricks-sdk mlflow packaging
dbutils.library.restartPython()

# COMMAND ----------

dbutils.widgets.dropdown("scan_mode", "current", ["current", "account", "urls"], "Scan mode")
dbutils.widgets.text("account_id", "", "Account ID (account mode)")
dbutils.widgets.text("account_host", "https://accounts.azuredatabricks.net", "Account host")
dbutils.widgets.text("secret_scope", "certifi-scan", "Secret scope (sp-client-id / sp-client-secret)")
dbutils.widgets.text("workspace_urls", "", "Workspace URLs, comma separated (urls mode)")
me = spark.sql("SELECT current_user()").first()[0]
dbutils.widgets.text("workspace_roots", f"/Users/{me}", "Code roots to scan, comma separated ('/' = everything)")
dbutils.widgets.text("running_hours", "24", "Restart threshold (hours)")
dbutils.widgets.dropdown("scan_volumes", "no", ["no", "yes"], "Walk all volumes in 3b")
dbutils.widgets.dropdown("create_fixtures", "no", ["no", "yes"], "Create test fixtures")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Setup: connect to the workspaces

# COMMAND ----------

import re, os, tempfile
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version
from databricks.sdk import AccountClient, WorkspaceClient
from databricks.sdk.service.workspace import ObjectType, ExportFormat

MODE          = dbutils.widgets.get("scan_mode")
ROOTS         = [r.strip() for r in dbutils.widgets.get("workspace_roots").split(",") if r.strip()]
RUNNING_HOURS = float(dbutils.widgets.get("running_hours"))

if MODE == "current":
    w_here = WorkspaceClient()
    WORKSPACES = [(w_here.config.host, w_here)]
else:
    scope = dbutils.widgets.get("secret_scope")
    CID, SEC = dbutils.secrets.get(scope, "sp-client-id"), dbutils.secrets.get(scope, "sp-client-secret")
    if MODE == "urls":
        urls = [u.strip() for u in dbutils.widgets.get("workspace_urls").split(",") if u.strip()]
        WORKSPACES = [(u, WorkspaceClient(host=u, client_id=CID, client_secret=SEC, auth_type="oauth-m2m")) for u in urls]
    else:
        acct = AccountClient(host=dbutils.widgets.get("account_host"), account_id=dbutils.widgets.get("account_id"),
                             client_id=CID, client_secret=SEC, auth_type="oauth-m2m")
        WORKSPACES = []
        for ws in acct.workspaces.list():
            if ws.workspace_status and ws.workspace_status.value != "RUNNING":
                continue
            try:
                WORKSPACES.append((ws.workspace_name, acct.get_workspace_client(ws)))
            except Exception as e:
                print(f"could not connect to {ws.workspace_name}: {e}")
print(f"{len(WORKSPACES)} workspace(s): {[n for n, _ in WORKSPACES][:10]}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Optional: test fixtures
# MAGIC With `create_fixtures = yes`, this writes a small test folder to your home directory. It contains a pinned requirements.txt, a notebook-style .py file with `%pip install certifi==2024.2.2`, and a clean file, so you can confirm Script 3a flags the right things. Delete the folder when you're done.

# COMMAND ----------

if dbutils.widgets.get("create_fixtures") == "yes":
    base = f"/Workspace/Users/{me}/certifi_scan_fixtures"
    os.makedirs(base, exist_ok=True)
    files = {
        "requirements.txt": "requests==2.32.3\ncertifi==2024.2.2\n",          # expect ACTION
        "requirements-ok.txt": "certifi>=2026.10.19\n",                       # expect nothing
        "pinned_job.py": "# %pip install certifi==2024.2.2\nimport certifi\n", # expect ACTION + REVIEW
        "uv.lock": 'version = 1\n[[package]]\nname = "certifi"\nversion = "2025.11.12"\n',  # expect ACTION
    }
    for fn, body in files.items():
        with open(f"{base}/{fn}", "w") as f:
            f.write(body)
    print(f"fixtures written to {base}")
else:
    print("skipped")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Script 1: workspace inventory (the checklist)

# COMMAND ----------

inv = []
for name, w in WORKSPACES:
    row = dict(workspace=name, apps=0, serving_custom_models=0, custom_image_clusters=0,
               all_purpose_clusters=0, error="")
    try:
        row["apps"] = sum(1 for _ in w.apps.list())
    except Exception as e:
        row["error"] += f"apps: {str(e)[:150]}; "
    try:
        for ep in w.serving_endpoints.list():
            cfg = w.serving_endpoints.get(ep.name).config
            row["serving_custom_models"] += sum(
                1 for e in ((cfg.served_entities if cfg else None) or [])
                if e.entity_name and not e.external_model and not e.foundation_model
                and not e.entity_name.startswith("system."))
    except Exception as e:
        row["error"] += f"serving: {str(e)[:150]}; "
    try:
        for c in w.clusters.list():
            row["custom_image_clusters"] += 1 if c.docker_image else 0
            src = c.cluster_source.value if c.cluster_source else ""
            row["all_purpose_clusters"] += 1 if src in ("UI", "API") else 0
    except Exception as e:
        row["error"] += f"clusters: {str(e)[:150]}; "
    inv.append(row)

display(spark.createDataFrame(inv, "workspace string, apps int, serving_custom_models int, custom_image_clusters int, "
                                   "all_purpose_clusters int, error string").orderBy("workspace"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Script 2: restart list (clusters running longer than the threshold)
# MAGIC Stopped clusters aren't listed, because they pick up the patch on their next start. Job clusters are included so that always-on jobs show up.

# COMMAND ----------

now, rst = datetime.now(timezone.utc), []
for name, w in WORKSPACES:
    try:
        for c in w.clusters.list():
            if not c.state or c.state.value != "RUNNING":
                continue
            started = c.last_restarted_time or c.start_time
            if not started:
                continue
            since = datetime.fromtimestamp(started / 1000, tz=timezone.utc)
            hours = round((now - since).total_seconds() / 3600, 1)
            if hours > RUNNING_HOURS:
                tags = c.default_tags or {}
                rst.append((name, c.cluster_name or "", c.cluster_source.value if c.cluster_source else "",
                            c.spark_version or "", c.creator_user_name or "", tags.get("JobId", ""),
                            tags.get("RunName", ""), since.isoformat(), float(hours),
                            c.docker_image.url if c.docker_image else ""))
    except Exception as e:
        print(f"{name}: {e}")

display(spark.createDataFrame(rst, "workspace string, cluster string, source string, runtime string, creator string, "
                                   "job_id string, run_name string, running_since string, hours double, custom_image string")
        .orderBy("hours", ascending=False))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Script 3 helpers: what counts as a finding
# MAGIC - **ACTION**: a certifi pin or lock-file version that blocks 2026.10.19+, or an old copied certifi package
# MAGIC - **REVIEW**: certifi is mentioned, or something needs a manual check (Git code, custom image, init script, unreadable file)
# MAGIC - **REDEPLOY**: an app that should be redeployed on or after Nov 12

# COMMAND ----------

FIXED = Version("2026.10.19")
REQ   = re.compile(r"certifi\s*((?:[<>=!~]=?)\s*[0-9][\w.*]*(?:\s*,\s*(?:[<>=!~]=?)\s*[0-9][\w.*]*)*)", re.I)
LOCK  = re.compile(r'name\s*=\s*"certifi"\s*\r?\n\s*version\s*=\s*"([^"]+)"', re.I)
WHEEL = re.compile(r"^certifi-(\d[\w.]*?)(?:-py|\.tar\.gz|\.zip)", re.I)
INITV = re.compile(r"""__version__\s*=\s*["']([^"']+)""")
DEP   = re.compile(r"(requirements.*\.txt|constraints.*\.txt|\.lock|pyproject\.toml|(environment|conda)\.ya?ml)$", re.I)

def old(v):
    try:
        return Version(v) < FIXED
    except Exception:
        return True

def bad_pins(text):
    """certifi pins / locked versions that block 2026.10.19+."""
    out = []
    for m in REQ.finditer(text or ""):
        s = m.group(1).replace(" ", "")
        s = "=" + s if re.match(r"^=[^=]", s) else s      # conda style certifi=x
        try:
            if not SpecifierSet(s).contains(FIXED, prereleases=True):
                out.append(f"certifi{s}")
        except InvalidSpecifier:
            out.append(f"certifi{s} (check by hand)")
    out += [f"certifi {m.group(1)} (lock file)" for m in LOCK.finditer(text or "") if old(m.group(1))]
    return sorted(set(out))

def grep(text):
    """Line scan: bad pin = ACTION, any other certifi mention = REVIEW."""
    res = []
    for line in (text or "").splitlines():
        if "certifi" in line.lower():
            hits = bad_pins(line)
            res += [("ACTION", h, line.strip()[:200]) for h in hits] or \
                   [("REVIEW", "mentions certifi", line.strip()[:200])]
    return res

def copied_certifi(path, read):
    """Someone copied the certifi package itself (wheel, folder, CA bundle)."""
    fn, low = path.rsplit("/", 1)[-1], path.lower()
    m = WHEEL.search(fn)
    if m:
        return [("ACTION", f"certifi package {m.group(1)}")] if old(m.group(1)) else []
    if low.endswith("/certifi/__init__.py"):
        v = INITV.search(read(path) or "")
        if not v:
            return [("REVIEW", "copied certifi, version not found")]
        return [("ACTION", f"copied certifi {v.group(1)}")] if old(v.group(1)) else []
    if low.endswith("cacert.pem") and "emsign" in (read(path) or "").lower():
        return [("REVIEW", "CA bundle copy lists emSign, confirm it is from certifi 2026.10.19+")]
    return []

def ws_read(w, p):
    p = p.replace("dbfs:", "")
    try:
        if p.startswith("/Volumes"):
            return w.files.download(p).contents.read().decode("utf-8", "ignore")
        p = p[len("/Workspace"):] if p.startswith("/Workspace/") else p
        with w.workspace.download(p, format=ExportFormat.AUTO) as f:
            return f.read().decode("utf-8", "ignore")
    except Exception:
        return None

def custodian(p):
    m = re.match(r"^/(?:Workspace/)?(?:Users|Repos)/([^/]+)", p)
    return m.group(1) if m else "check permissions"

# quick self-test of the matching logic
assert bad_pins("certifi==2024.2.2") == ["certifi==2024.2.2"]
assert bad_pins("certifi<2025") == ["certifi<2025"]
assert bad_pins("certifi>=2026.10.19") == []
assert bad_pins("certifi") == []
assert bad_pins('name = "certifi"\nversion = "2025.11.12"') == ["certifi 2025.11.12 (lock file)"]
assert copied_certifi("/x/certifi-2024.2.2-py3-none-any.whl", lambda p: "")[0][0] == "ACTION"
print("matching logic OK")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Script 3a: certifi scan per workspace (code, jobs, apps, cluster libraries)
# MAGIC On a large workspace the code scan is the slow part, because it exports every notebook under `workspace_roots`.

# COMMAND ----------

findings, served = [], []
for name, w in WORKSPACES:
    def add(sev, kind, asset, owner, what, where=""):
        findings.append((name, sev, kind, str(asset), str(owner or ""), str(what), str(where)))
    print(f"scanning {name}")
    try:
        ms = w.metastores.current().metastore_id
    except Exception:
        ms = ""

    # Notebooks, .py files, requirements/lock files, copied certifi (app source in the workspace is covered too)
    def scan(o):
        low, out = o.path.lower(), []
        if o.object_type == ObjectType.NOTEBOOK:
            out += [(s, "Notebook", h, l) for s, h, l in grep(ws_read(w, o.path))]
        elif o.object_type == ObjectType.FILE:
            if DEP.search(low):
                out += [("ACTION", "Dependency file", h, "") for h in bad_pins(ws_read(w, o.path))]
            elif low.endswith(".py") and not low.endswith("/certifi/__init__.py"):
                out += [(s, "Python file", h, l) for s, h, l in grep(ws_read(w, o.path))]
            out += [(s, "Copied certifi", h, "") for s, h in copied_certifi(o.path, lambda p: ws_read(w, p))]
        return [(o.path,) + x for x in out]

    for root in ROOTS:
        try:
            objs = [o for o in w.workspace.list(root, recursive=True)
                    if o.object_type in (ObjectType.NOTEBOOK, ObjectType.FILE)]
            print(f"  {root}: {len(objs)} notebooks/files")
            with ThreadPoolExecutor(8) as ex:
                for res in ex.map(scan, objs):
                    for path, sev, kind, h, line in res:
                        add(sev, kind, path, custodian(path), h, line)
        except Exception as e:
            add("REVIEW", "Workspace", name, "", f"code scan of {root} failed: {str(e)[:200]}")

    # Jobs: serverless environments, libraries, requirements files, Git-backed code
    try:
        for j in w.jobs.list(expand_tasks=True):
            s = j.settings
            if not s:
                continue
            ra = getattr(s, "run_as", None)
            owner = (ra and (ra.user_name or ra.service_principal_name)) or j.creator_user_name
            label = f"{s.name} (job {j.job_id})"
            if getattr(s, "git_source", None):
                add("REVIEW", "Job", label, owner, "code is in Git, scan the repo", s.git_source.git_url)
            for env in (s.environments or []):
                for d in ((env.spec.dependencies if env.spec else None) or []):
                    txt = ws_read(w, d.strip()[2:].strip()) if d.strip().startswith("-r") else d
                    for h in bad_pins(txt):
                        add("ACTION", "Job environment", label, owner, h, d)
            for t in (s.tasks or []):
                for lib in (t.libraries or []):
                    if lib.pypi and lib.pypi.package:
                        for h in bad_pins(lib.pypi.package):
                            add("ACTION", "Job library", label, owner, h, t.task_key)
                    if lib.requirements:
                        for h in bad_pins(ws_read(w, lib.requirements)):
                            add("ACTION", "Job library", label, owner, h, lib.requirements)
    except Exception as e:
        add("REVIEW", "Workspace", name, "", f"job scan failed: {str(e)[:200]}")

    # Apps: everyone redeploys; flag pins in the deployed source
    try:
        for app in w.apps.list():
            add("REDEPLOY", "App", app.name, app.creator, "redeploy on or after Nov 12, non-prod first")
            src = app.active_deployment.source_code_path if app.active_deployment else None
            for fn in (["requirements.txt", "uv.lock", "poetry.lock", "pyproject.toml"] if src else []):
                for h in bad_pins(ws_read(w, f"{src.rstrip('/')}/{fn}")):
                    add("ACTION", "App", app.name, app.creator, h, fn)
    except Exception as e:
        add("REVIEW", "Workspace", name, "", f"app scan failed: {str(e)[:200]}")

    # Classic clusters: installed libraries, init scripts, custom images
    try:
        libs = {}
        try:
            res = w.libraries.all_cluster_statuses()
            libs = {cs.cluster_id: cs.library_statuses or [] for cs in (getattr(res, "statuses", None) or res)}
        except Exception as e:
            add("REVIEW", "Workspace", name, "", f"cluster library listing failed: {str(e)[:200]}")
        for c in w.clusters.list():
            label = f"{c.cluster_name} ({c.spark_version})"
            if c.docker_image:
                add("REVIEW", "Cluster", label, c.creator_user_name, "custom image, scan it for eMudhra CAs", c.docker_image.url)
            if c.init_scripts:
                add("REVIEW", "Cluster", label, c.creator_user_name, "has init scripts, check for certifi or CA files")
            for ls in libs.get(c.cluster_id, []):
                if ls.library and ls.library.pypi and ls.library.pypi.package:
                    for h in bad_pins(ls.library.pypi.package):
                        add("ACTION", "Cluster library", label, c.creator_user_name, h)
    except Exception as e:
        add("REVIEW", "Workspace", name, "", f"cluster scan failed: {str(e)[:200]}")

    # Model serving: collect the custom models being served, checked in 3b
    try:
        for ep in w.serving_endpoints.list():
            full = w.serving_endpoints.get(ep.name)
            for e in ((full.config.served_entities if full.config else None) or []):
                if e.entity_name and not e.external_model and not e.foundation_model \
                        and not e.entity_name.startswith("system."):
                    served.append((name, ms, ep.name, full.creator or "", e.entity_name, str(e.entity_version)))
    except Exception as e:
        add("REVIEW", "Workspace", name, "", f"serving scan failed: {str(e)[:200]}")

fnd_df = spark.createDataFrame(findings, "workspace string, severity string, type string, asset string, "
                                         "custodian string, finding string, location string")
print(f"{len(findings)} findings, {len(served)} served custom models")
display(fnd_df.orderBy("severity", "workspace", "custodian"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Script 3b: certifi scan per metastore (served models, UC Python UDFs, volumes)
# MAGIC Run this once in a workspace attached to each metastore. It uses the served-model list from 3a in the same session. Walking every volume can be slow, so it's off by default (`scan_volumes`).

# COMMAND ----------

import mlflow
w0 = WorkspaceClient()
ms_here = w0.metastores.current().metastore_id
mlflow.set_registry_uri("databricks-uc")

def local(p):
    try:
        with open(p, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None

f2 = []
def add2(sev, kind, asset, owner, what, where=""):
    f2.append((sev, kind, str(asset), str(owner or ""), str(what), str(where)))

# Model serving: requirements of the model version each endpoint serves
for ws_name, ms_id, ep, creator, model, ver in sorted(set(served)):
    if ms_id and ms_id != ms_here:
        continue
    if model.count(".") != 2:
        add2("REVIEW", "Model Serving", f"{ep} ({ws_name})", creator,
             "workspace-registry model, check its requirements.txt", f"{model} v{ver}")
        continue
    txt = ""
    for fn in ("requirements.txt", "conda.yaml"):
        try:
            p = mlflow.artifacts.download_artifacts(artifact_uri=f"models:/{model}/{ver}/{fn}", dst_path=tempfile.mkdtemp())
            txt += (local(p) or "") + "\n"
        except Exception:
            pass
    if not txt.strip():
        add2("REVIEW", "Model Serving", f"{ep} ({ws_name})", creator, "could not read requirements", f"{model} v{ver}")
    for h in bad_pins(txt):
        add2("ACTION", "Model Serving", f"{ep} ({ws_name})", creator, h, f"{model} v{ver}")

# UC Python UDFs: ENVIRONMENT dependencies
for r in spark.sql("""SELECT routine_catalog, routine_schema, routine_name
                      FROM system.information_schema.routines
                      WHERE upper(external_language) = 'PYTHON'""").collect():
    fq = f"{r[0]}.{r[1]}.{r[2]}"
    try:
        desc = "\n".join(" ".join(map(str, x)) for x in
                          spark.sql(f"DESCRIBE FUNCTION EXTENDED `{r[0]}`.`{r[1]}`.`{r[2]}`").collect())
        hits = bad_pins(desc)
        if hits:
            owner = w0.functions.get(fq).owner
            for h in hits:
                add2("ACTION", "UC Python UDF", fq, owner, h)
    except Exception as e:
        add2("REVIEW", "UC Python UDF", fq, "", f"could not check: {str(e)[:120]}")

# Volumes: dependency files and copies of certifi
if dbutils.widgets.get("scan_volumes") == "yes":
    for v in spark.sql("SELECT volume_catalog, volume_schema, volume_name, volume_owner "
                       "FROM system.information_schema.volumes").collect():
        root = f"/Volumes/{v[0]}/{v[1]}/{v[2]}"
        try:
            for d, _, files in os.walk(root):
                for fn in files:
                    p = os.path.join(d, fn)
                    if DEP.search(fn):
                        for h in bad_pins(local(p)):
                            add2("ACTION", "Volume file", p, v[3], h)
                    for s, h in copied_certifi(p, local):
                        add2(s, "Copied certifi", p, v[3], h)
        except Exception as e:
            add2("REVIEW", "Volume", root, v[3], f"could not walk: {str(e)[:120]}")

f2_df = spark.createDataFrame(f2, "severity string, type string, asset string, custodian string, finding string, location string")
print(f"metastore {ms_here}: {len(f2)} findings")
display(f2_df.orderBy("severity", "custodian"))
