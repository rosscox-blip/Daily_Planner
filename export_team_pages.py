#!/usr/bin/env python3
"""
export_team_pages.py
Generate one self-contained HTML page per team member and deploy to GitHub Pages
via a git push. Runs via Windows Task Scheduler — see run_export.bat.

Security model:
  - HTML pages contain NO job data — just the member name and config constants
  - Job data is AES-256-GCM encrypted in data/<member>.json (PBKDF2 key derivation, 100k iterations)
  - Each member has their own password; a master password (Ross) can open any page
  - Even direct access to the JSON file yields only ciphertext
"""
import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as _hashes

from dotenv import load_dotenv
load_dotenv()

SCRIPT_DIR = Path(__file__).resolve().parent
IN_CI      = os.environ.get('CI', '').lower() == 'true'

# Local: script lives in DailyPlanner/, output goes to DailyPlanner/team_pages/
# CI:    script lives in repo root (= team_pages/), output goes to ./
if IN_CI:
    PAGES_DIR = SCRIPT_DIR
else:
    _tp = SCRIPT_DIR / 'team_pages'
    PAGES_DIR = _tp if _tp.is_dir() else SCRIPT_DIR

sys.path.insert(0, str(SCRIPT_DIR))
import config as planner_config
GITHUB_TOKEN    = os.environ.get('GITHUB_TOKEN', '')
GITHUB_REPO     = os.environ.get('GITHUB_REPO', 'rosscox-blip/Daily_Planner')
MASTER_PASSWORD = os.environ.get('MASTER_PASSWORD', '')

MEMBER_PASSWORDS = {
    'emie':    os.environ.get('EMIE_PASSWORD', ''),
    'jay':     os.environ.get('JAY_PASSWORD', ''),
    'rob':     os.environ.get('ROB_PASSWORD', ''),
    'ross':    os.environ.get('ROSS_PASSWORD', ''),
    'sofia':   os.environ.get('SOFIA_PASSWORD', ''),
    'suna':    os.environ.get('SUNA_PASSWORD', ''),
    'tristan': os.environ.get('TRISTAN_PASSWORD', ''),
    'joe':     os.environ.get('JOE_PASSWORD', ''),
    'anna':    os.environ.get('ANNA_PASSWORD', ''),
}

MASTER_PW_HASH = hashlib.sha256(MASTER_PASSWORD.encode()).hexdigest()


def _member_pw_hash(member_lower: str) -> str:
    pw = MEMBER_PASSWORDS.get(member_lower, '')
    return hashlib.sha256(pw.encode()).hexdigest()
TEAM_MEMBERS = ['Emie', 'Jay', 'Rob', 'Ross', 'Sofia', 'Suna', 'Tristan']

MEMBER_EMAILS = {
    'emie':    'emievic.yousaf@arrive.com',
    'jay':     'jayprakash.basaliyal@arrive.com',
    'rob':     'robert.smith@arrive.com',
    'ross':    'ross.cox@arrive.com',
    'sofia':   'sofia.bater@arrive.com',
    'suna':    'suna.olgac@arrive.com',
    'tristan': 'tristan.pointer@arrive.com',
}

BO_MEMBERS = ['Joe', 'Anna']
BO_MEMBER_EMAILS = {
    'joe':  'joe.stanton@arrive.com',
    'anna': 'anna.kulesza@arrive.com',
}

# Default category tab for the unassigned jobs section
MEMBER_CATEGORY = {
    'emie': 'CWT', 'jay': 'CWT', 'tristan': 'CWT', 'ross': 'CWT',
    'sofia': 'NEOPS', 'suna': 'NEOPS', 'rob': 'NEOPS',
}

# Add entries here to update all team pages. Newest first.
# Format: {'date': 'DD Mon YYYY', 'title': '...', 'body': '...'}
CHANGELOG = [
    {'date': '05 Aug 2026', 'title': 'Fixed: "Updated" timestamp was showing wrong time', 'body': 'The timestamp at the top of your portal now shows when data was last exported, not when you refreshed the page.'},
    {'date': '05 Aug 2026', 'title': 'Back-office: "Update Trello = Done" override', 'body': "For Joe & Anna — when the Update Trello column is Done the whole job is marked complete, regardless of any other task columns."},
    {'date': '04 Aug 2026', 'title': 'Brute-force lockout', 'body': '5 wrong password attempts triggers a 2-minute lockout. Prevents automated guessing. Resets when the timer expires or you close the tab.'},
    {'date': '04 Aug 2026', 'title': 'AES-256 encryption for all job data', 'body': 'All data files are now encrypted end-to-end. Only your personal password can decrypt your jobs.'},
    {'date': '30 Jul 2026', 'title': 'Accent colour picker — all portals', 'body': 'Click your avatar circle on the login screen to change your personal accent colour. Saved in your browser.'},
    {'date': '30 Jul 2026', 'title': 'Team portals launched', 'body': 'Personal job dashboards rolled out to all team members. Updated hourly direct from the team Google Sheet.'},
]


# ── Data fetch ────────────────────────────────────────────────────────────────

def fetch_data():
    from agents.customisations_agent import CustomisationsAgent
    agent = CustomisationsAgent()
    agent.poll()
    if agent.status != 'ok':
        raise RuntimeError(f"Agent poll failed: {agent.error}")
    return agent.data


# ── HTML helpers ──────────────────────────────────────────────────────────────

def _j(obj):
    return json.dumps(obj, ensure_ascii=True).replace('</script>', r'<\/script>')


def _encrypt_blob(plaintext: str, password: str) -> dict:
    """AES-256-GCM encrypt plaintext using PBKDF2-derived key. Returns base64-encoded salt/iv/ct."""
    salt = secrets.token_bytes(16)
    kdf  = PBKDF2HMAC(algorithm=_hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    key  = kdf.derive(password.encode())
    iv   = secrets.token_bytes(12)
    ct   = AESGCM(key).encrypt(iv, plaintext.encode(), None)
    return {
        's': base64.b64encode(salt).decode(),
        'i': base64.b64encode(iv).decode(),
        'c': base64.b64encode(ct).decode(),
    }


def _make_payload(data: dict, member_pw: str) -> str:
    """Return JSON string: {v:1, m:<member-encrypted>, x:<master-encrypted>}."""
    plaintext = json.dumps(data, ensure_ascii=True)
    return json.dumps({
        'v': 1,
        'm': _encrypt_blob(plaintext, member_pw),
        'x': _encrypt_blob(plaintext, MASTER_PASSWORD),
    }, ensure_ascii=True)


def _validate_passwords():
    """Abort immediately if any password is missing — prevents deploying pages with empty-string keys."""
    missing = [name.upper() for name, pw in MEMBER_PASSWORDS.items() if not pw]
    if not MASTER_PASSWORD:
        missing.append('MASTER')
    if missing:
        raise SystemExit(
            f"\nERROR: Passwords not set for: {', '.join(missing)}\n"
            f"Make sure .env is loaded and contains all *_PASSWORD= entries.\n"
            f"Deploy aborted — no files were changed."
        )


def generate_member_html(member):
    email    = MEMBER_EMAILS.get(member.lower(), '')
    cap2w    = planner_config.WEEKLY_CAPACITY * 2
    lh_json  = json.dumps(planner_config.LEVEL_HOURS)
    category = MEMBER_CATEGORY.get(member.lower(), 'CWT')
    return (MEMBER_TEMPLATE
            .replace('%%MEMBER%%', member)
            .replace('%%MEMBER_LOWER%%', member.lower())
            .replace('%%INITIAL%%', member[0].upper())
            .replace('%%MEMBER_EMAIL%%', email)
            .replace('%%MEMBER_PW_HASH%%', _member_pw_hash(member.lower()))
            .replace('%%CAP2W%%', str(cap2w))
            .replace('%%LH_JSON%%', lh_json)
            .replace('%%MEMBER_CATEGORY%%', category)
            .replace('%%CHANGELOG_JSON%%', _j(CHANGELOG)))


def _build_changelog_html():
    if not CHANGELOG:
        return '<div class="cl-empty">No updates yet.</div>'
    items = ''.join(
        f'<div class="cl-item">'
        f'<div class="cl-date">{c["date"]}</div>'
        f'<div class="cl-body"><div class="cl-title">{c["title"]}</div>'
        f'<div class="cl-desc">{c.get("body", "")}</div></div>'
        f'</div>'
        for c in CHANGELOG
    )
    return f'<div class="cl-list">{items}</div>'


def generate_index_html(members):
    links = '\n'.join(
        f'<a href="{m.lower()}.html" class="member-link">'
        f'<span class="mi">{m[0]}</span><span class="mn">{m}</span></a>'
        for m in members
    )
    return (INDEX_TEMPLATE
            .replace('%%MEMBER_LINKS%%', links)
            .replace('%%CHANGELOG_HTML%%', _build_changelog_html()))


# ── Static site infrastructure files ─────────────────────────────────────────

NETLIFY_TOML = """\
[build]
  publish = "."

[functions]
  directory = "netlify/functions"

[[redirects]]
  from = "/netlify/functions/data/*"
  to   = "/404.html"
  status = 404
  force  = true
"""

JOBS_FUNCTION = """\
// netlify/functions/jobs.js
// Returns the authenticated team member's job data.
// Netlify automatically verifies the Identity JWT and injects context.clientContext.user.
const fs   = require('fs');
const path = require('path');

const ADMIN_EMAIL = 'ross.cox@arrive.com';

const EMAIL_MAP = {
  'emievic.yousaf@arrive.com':       'emie',
  'jayprakash.basaliyal@arrive.com': 'jay',
  'robert.smith@arrive.com':         'rob',
  'ross.cox@arrive.com':             'ross',
  'sofia.bater@arrive.com':          'sofia',
  'suna.olgac@arrive.com':           'suna',
  'tristan.pointer@arrive.com':      'tristan',
  'joe.stanton@arrive.com':          'joe',
  'anna.kulesza@arrive.com':         'anna',
};

exports.handler = async (event, context) => {
  const { user } = context.clientContext || {};

  if (!user) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Not authenticated' }) };
  }

  const userEmail = user.email.toLowerCase();
  let member;

  if (userEmail === ADMIN_EMAIL) {
    // Admin can view any member's page — page passes ?member= in the request
    member = (event.queryStringParameters || {}).member || '';
    if (!member) {
      return { statusCode: 400, body: JSON.stringify({ error: 'member param required' }) };
    }
  } else {
    member = EMAIL_MAP[userEmail];
    if (!member) {
      return { statusCode: 403, body: JSON.stringify({ error: 'Not authorised' }) };
    }
  }

  const dataPath = path.join(__dirname, 'data', member + '.json');
  try {
    const data = fs.readFileSync(dataPath, 'utf8');
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: data,
    };
  } catch (e) {
    return { statusCode: 404, body: JSON.stringify({ error: 'Data file not found' }) };
  }
};
"""


def write_infrastructure(pages_dir: Path):
    """Write netlify.toml and the jobs function (idempotent)."""
    (pages_dir / 'netlify.toml').write_text(NETLIFY_TOML, encoding='utf-8')
    fn_dir = pages_dir / 'netlify' / 'functions'
    fn_dir.mkdir(parents=True, exist_ok=True)
    (fn_dir / 'jobs.js').write_text(JOBS_FUNCTION, encoding='utf-8')


def write_data_files(pages_dir: Path, all_jobs, all_completed):
    """Write per-member JSON data files served as static files by GitHub Pages."""
    data_dir = pages_dir / 'data'
    data_dir.mkdir(parents=True, exist_ok=True)

    # Unassigned jobs split by model type (same for all members — toggle selects category)
    unassigned = [j for j in all_jobs
                  if not (j.get('allocated_to') or '').strip()
                  or (j.get('allocated_to') or '').lower() in ('unallocated', 'unassigned')]
    cwt_jobs   = [j for j in unassigned if 'cwt'   in (j.get('model') or '').lower()]
    neops_jobs = [j for j in unassigned if 'neops' in (j.get('model') or '').lower()]

    for member in TEAM_MEMBERS:
        lc   = member.lower()
        jobs = [j for j in all_jobs      if (j.get('allocated_to') or '').lower() == lc]
        comp = [j for j in all_completed if (j.get('allocated_to') or '').lower() == lc]
        member_pw = MEMBER_PASSWORDS.get(lc, '')
        payload = _make_payload({
            'jobs': jobs,
            'completed': comp,
            'unassigned_cwt': cwt_jobs,
            'unassigned_neops': neops_jobs,
            'generated_at': datetime.now().strftime('%H:%M'),
        }, member_pw)
        (data_dir / f'{lc}.json').write_text(payload, encoding='utf-8')
        print(f'  {member}: {len(jobs)} active, {len(comp)} completed, '
              f'{len(cwt_jobs)} unassigned CWT, {len(neops_jobs)} unassigned NEOPS')


def write_joe_anna_data(pages_dir: Path, bo_jobs, bo_completed, all_sw_jobs):
    """Write per-member JSON for Joe and Anna, cross-referenced with SW go-live dates."""
    data_dir = pages_dir / 'data'
    data_dir.mkdir(parents=True, exist_ok=True)

    sw_go_live = {}
    for j in all_sw_jobs:
        ref = (j.get('reference') or '').strip()
        if ref and j.get('due_date') and ref not in sw_go_live:
            sw_go_live[ref] = j['due_date']

    # Apply SW go-live to all BO jobs up front
    for job in bo_jobs + bo_completed:
        job['sw_go_live_date'] = sw_go_live.get(job.get('reference', ''), '')

    for member in BO_MEMBERS:
        lc   = member.lower()
        jobs = [j for j in bo_jobs      if j.get('owned_by', '') == lc]
        comp = [j for j in bo_completed if j.get('owned_by', '') == lc]
        member_pw = MEMBER_PASSWORDS.get(lc, '')
        payload = _make_payload({
            'jobs':          jobs,
            'completed':     comp,
            'all_jobs':      bo_jobs,
            'all_completed': bo_completed,
            'generated_at':  datetime.now().strftime('%H:%M'),
        }, member_pw)
        (data_dir / f'{lc}.json').write_text(payload, encoding='utf-8')
        print(f'  {member} (BO): {len(jobs)} active, {len(comp)} completed')


def generate_joe_anna_html(member):
    email = BO_MEMBER_EMAILS.get(member.lower(), '')
    return (JOE_ANNA_TEMPLATE
            .replace('%%MEMBER%%', member)
            .replace('%%MEMBER_LOWER%%', member.lower())
            .replace('%%INITIAL%%', member[0].upper())
            .replace('%%MEMBER_EMAIL%%', email)
            .replace('%%MEMBER_PW_HASH%%', _member_pw_hash(member.lower()))
            .replace('%%CHANGELOG_JSON%%', _j(CHANGELOG)))


# ── CI source sync ───────────────────────────────────────────────────────────

def _sync_source_to_repo():
    """Keep the GitHub Actions runner up to date by copying source files into
    PAGES_DIR before every push. GitHub Actions reads from these copies."""
    # Script itself
    shutil.copy2(Path(__file__), PAGES_DIR / 'export_team_pages.py')

    # Agent modules
    agents_dest = PAGES_DIR / 'agents'
    agents_dest.mkdir(exist_ok=True)
    (agents_dest / '__init__.py').write_text('', encoding='utf-8')
    for src in (SCRIPT_DIR / 'agents').glob('*.py'):
        shutil.copy2(src, agents_dest / src.name)

    # Minimal config for CI — all values agents may reference
    (PAGES_DIR / 'config.py').write_text(
        f'WEEKLY_CAPACITY = {planner_config.WEEKLY_CAPACITY}\n'
        f'LEVEL_HOURS = {json.dumps(planner_config.LEVEL_HOURS)}\n'
        'USE_MOCK_DATA = False\n'
        'USE_MOCK_CUSTOMISATIONS = False\n'
        'USE_MOCK_BANKING = False\n'
        'USE_MOCK_EMAIL = False\n'
        'USE_MOCK_SERVICENOW = False\n'
        'USE_MOCK_PROJECTS = False\n',
        encoding='utf-8'
    )


# ── GitHub Pages deploy ───────────────────────────────────────────────────────

def _git(*args, check=True):
    r = subprocess.run(['git'] + list(args), cwd=PAGES_DIR,
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}:\n{r.stderr.strip()}")
    return r.stdout.strip()


def setup_git():
    PAGES_DIR.mkdir(exist_ok=True)
    remote = f'https://{GITHUB_TOKEN}@github.com/{GITHUB_REPO}.git'
    if not (PAGES_DIR / '.git').exists():
        _git('init', '-b', 'main')
        _git('remote', 'add', 'origin', remote)
    else:
        _git('remote', 'set-url', 'origin', remote)
    _git('config', 'user.email', 'daily-planner@arrive.com')
    _git('config', 'user.name', 'Daily Planner')


def push(generated_at):
    _git('add', '-A')
    if not _git('status', '--porcelain', check=False):
        print('  Nothing to commit — pages unchanged.')
        return
    _git('commit', '-m', f'Update team pages — {generated_at}')
    try:
        _git('push', '-u', 'origin', 'main')
    except RuntimeError:
        _git('push', '-u', 'origin', 'main', '--force')
    print(f'  Pushed — https://rosscox-blip.github.io/Daily_Planner/')


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    _validate_passwords()
    ts = datetime.now()
    generated_at = ts.strftime('%d %b %Y, %H:%M')
    print(f'[{ts:%H:%M:%S}] Fetching data from Google Sheets...')

    data = fetch_data()
    all_jobs      = data.get('jobs', [])
    all_completed = data.get('completed_jobs', [])
    print(f'  {len(all_jobs)} active SW jobs, {len(all_completed)} completed')

    # Joe & Anna back-office data
    from agents.joe_anna_agent import JoeAnnaAgent
    bo_agent = JoeAnnaAgent()
    bo_agent.poll()
    bo_data      = bo_agent.get_data() if bo_agent.status == 'ok' else {}
    bo_jobs      = bo_data.get('jobs', [])
    bo_completed = bo_data.get('completed_jobs', [])
    print(f'  {len(bo_jobs)} active BO jobs, {len(bo_completed)} completed')

    if not IN_CI:
        setup_git()

    (PAGES_DIR / '.nojekyll').write_text('', encoding='utf-8')

    write_data_files(PAGES_DIR, all_jobs, all_completed)
    write_joe_anna_data(PAGES_DIR, bo_jobs, bo_completed, all_jobs)

    all_members = TEAM_MEMBERS + BO_MEMBERS
    for member in TEAM_MEMBERS:
        html = generate_member_html(member)
        (PAGES_DIR / f'{member.lower()}.html').write_text(html, encoding='utf-8')
    for member in BO_MEMBERS:
        html = generate_joe_anna_html(member)
        (PAGES_DIR / f'{member.lower()}.html').write_text(html, encoding='utf-8')

    (PAGES_DIR / 'index.html').write_text(
        generate_index_html(all_members), encoding='utf-8')
    (PAGES_DIR / 'announce.html').write_text(
        ANNOUNCE_HTML, encoding='utf-8')
    print('  Generated HTML shells (no embedded job data)')

    if not IN_CI:
        _sync_source_to_repo()
        push(generated_at)
    print('Done.')


# ── Member page template ──────────────────────────────────────────────────────

MEMBER_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%%MEMBER%% &mdash; Work Planner</title>
<style>
/* ── Design tokens ───────────────────────────────────────────── */
:root{
  --bg:#0d0d1f;--bg2:#14142e;--card:#1c1c40;--border:#2a2a58;
  --text:#e0e0f4;--muted:#9090c0;--pink:#e91e8c;
  --nmo:#f97316;--hw:#3b82f6;--cr:#a855f7;
  --green:#22c55e;--amber:#f59e0b;--red:#ef4444;--r:8px;
  --bl-bg:rgba(255,255,255,.12);--bl-col:var(--text);
  --bst-bg:rgba(255,255,255,.08);
  --row-hover:rgba(255,255,255,.04);
  --band-lt-bg:rgba(255,255,255,.04);--band-un-bg:rgba(255,255,255,.025);
}
[data-theme="light"]{
  --bg:#f2f2fa;--bg2:#ffffff;--card:#ffffff;--border:#ccccdd;
  --text:#111111;--muted:#444444;
  --bl-bg:rgba(0,0,0,.1);--bl-col:#111111;
  --bst-bg:rgba(0,0,0,.08);
  --row-hover:rgba(0,0,0,.03);
  --band-lt-bg:rgba(0,0,0,.04);--band-un-bg:rgba(0,0,0,.025);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:var(--bg);color:var(--text);font-size:14px;line-height:1.5;min-height:100vh}

/* ── Auth overlay ────────────────────────────────────────────── */
#auth-overlay{position:fixed;inset:0;background:rgba(8,8,22,.97);
  display:flex;align-items:center;justify-content:center;z-index:9999}
[data-theme="light"] #auth-overlay{background:rgba(215,215,235,.97)}
#auth-box{background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:36px 32px;width:340px;text-align:center;display:flex;
  flex-direction:column;align-items:center;gap:14px}
#auth-avatar{width:56px;height:56px;border-radius:50%;background:var(--pink);
  display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:#fff}
#auth-name{font-size:1.1rem;font-weight:700}
#auth-sub{color:var(--muted);font-size:.82rem;line-height:1.5}
#auth-pw-input{width:100%;padding:10px 12px;border-radius:7px;font-size:.9rem;
  border:1px solid var(--border);background:var(--bg);color:var(--text);outline:none;transition:border .15s}
#auth-pw-input:focus{border-color:var(--pink)}
#auth-pw-submit{width:100%;background:var(--pink);color:#fff;border:none;
  padding:11px;border-radius:7px;font-size:.9rem;font-weight:700;cursor:pointer;transition:opacity .15s}
#auth-pw-submit:hover{opacity:.85}
#auth-pw-err{color:var(--red);font-size:.8rem;text-align:center}

/* ── Loading overlay ─────────────────────────────────────────── */
#load-overlay{position:fixed;inset:0;background:rgba(8,8,22,.92);
  display:none;align-items:center;justify-content:center;z-index:9998;
  flex-direction:column;gap:16px}
.load-spin{width:40px;height:40px;border:3px solid rgba(255,255,255,.1);
  border-top-color:var(--pink);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
#load-msg{color:var(--muted);font-size:.85rem}

/* ── Header ──────────────────────────────────────────────────── */
.hdr{background:var(--bg2);border-bottom:2px solid var(--pink);padding:16px 20px}
.hdr-inner{max-width:1200px;margin:0 auto;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.avatar-wrap{position:relative;flex-shrink:0;cursor:pointer}
.avatar-wrap:hover .avatar{opacity:.85}
.avatar{width:46px;height:46px;border-radius:50%;background:var(--pink);display:flex;
        align-items:center;justify-content:center;font-size:18px;font-weight:700;
        color:#fff;pointer-events:none;transition:opacity .15s}
#avatar-color-picker{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer;border:none;padding:0;border-radius:50%}
.hdr-name{font-size:1.35rem;font-weight:700;color:var(--text)}
.hdr-sub{color:var(--muted);font-size:0.78rem}
.hdr-ts{margin-left:auto;text-align:right;font-size:0.75rem;color:var(--muted);line-height:1.7}
.hdr-ts .cur-time{color:var(--text);font-size:1.1rem;font-weight:700;display:block;letter-spacing:.04em}
.hdr-ts .upd-time{color:var(--text);font-weight:600;font-size:.8rem;display:block}
.theme-btn{background:none;border:1px solid var(--border);color:var(--muted);
           padding:6px 12px;border-radius:6px;font-size:.76rem;cursor:pointer;
           white-space:nowrap;flex-shrink:0;transition:all .15s}
.theme-btn:hover{border-color:var(--pink);color:var(--pink)}
.back-btn{display:none;align-items:center;gap:6px;background:none;
          border:1px solid var(--border);color:var(--muted);
          padding:6px 12px;border-radius:6px;font-size:.76rem;cursor:pointer;
          white-space:nowrap;flex-shrink:0;transition:all .15s;text-decoration:none}
.back-btn:hover{border-color:var(--pink);color:var(--pink)}
.back-btn.visible{display:flex}

/* ── Nav ─────────────────────────────────────────────────────── */
.nav{background:var(--bg2);border-bottom:1px solid var(--border);
     position:sticky;top:0;z-index:100}
.nav-inner{max-width:1200px;margin:0 auto;display:flex;justify-content:space-between;align-items:center;padding-right:16px}
.nav-links{display:flex}
.nav a{padding:10px 22px;text-decoration:none;color:var(--muted);font-size:0.78rem;
       font-weight:700;text-transform:uppercase;letter-spacing:.06em;
       border-bottom:3px solid transparent;transition:all .15s}
.nav a:hover,.nav a.act{color:var(--pink);border-color:var(--pink)}
.nav-user{font-size:.72rem;color:var(--muted);display:flex;align-items:center;gap:8px}
.nav-signout{background:none;border:1px solid var(--border);color:var(--muted);
             padding:4px 10px;border-radius:5px;font-size:.7rem;cursor:pointer}
.nav-signout:hover{border-color:var(--red);color:var(--red)}

/* ── Main layout ─────────────────────────────────────────────── */
main{max-width:1200px;margin:0 auto;padding:28px 16px}
section{margin-bottom:52px}
.sec-hdr{margin-bottom:6px;display:flex;align-items:baseline;gap:10px}
.sec-hdr h2{font-size:1.05rem;font-weight:700;color:var(--text)}
.sec-cnt{background:var(--pink);color:#fff;font-size:.7rem;
         padding:2px 8px;border-radius:12px;font-weight:700}
.sec-sub{color:var(--muted);font-size:.78rem;margin-bottom:18px}

/* ── Capacity bar ────────────────────────────────────────────── */
.cap{background:var(--card);border:1px solid var(--border);border-radius:var(--r);
     padding:14px 18px;margin-bottom:22px}
[data-theme="light"] .cap{background:#f0f0fc;border-color:#c8c8e8}
.cap-lbl{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.cap-bg{background:var(--border);border-radius:4px;height:8px;margin-bottom:7px}
[data-theme="light"] .cap-bg{background:#d4d4ec}
.cap-fill{height:100%;border-radius:4px;transition:width .4s}
.cap-txt{font-size:.8rem;color:var(--muted)}
.cap-txt strong{color:var(--text)}

/* ── Priority grid ───────────────────────────────────────────── */
.pg{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:14px}
.p-empty{background:var(--card);border:1px solid var(--border);border-radius:var(--r);
         padding:24px;text-align:center;color:var(--green);font-size:.9rem}

/* ── Priority cards — DARK MODE ──────────────────────────────── */
.pc{background:#22224e;border:1px solid #36367a;border-left:4px solid #36367a;
    border-radius:var(--r);padding:14px;display:flex;flex-direction:column;gap:8px}
.pc.tnmo{background:#4a2a0a;border-color:#8a5020;border-left-color:var(--nmo)}
.pc.thw {background:#0a2448;border-color:#1848a0;border-left-color:var(--hw)}
.pc.tcr {background:#220a48;border-color:#5018a0;border-left-color:var(--cr)}
.pc.ovd {background:#480a0a;border-color:#a01818;border-left-color:var(--red)}

/* ── Priority cards — LIGHT MODE ─────────────────────────────── */
[data-theme="light"] .pc{background:#fff;border-color:#d4d4ec;border-left-color:#d4d4ec;
                          box-shadow:0 2px 8px rgba(0,0,0,.07)}
[data-theme="light"] .pc.tnmo{background:#fff8f2;border-color:rgba(249,115,22,.4);
                               border-left-color:var(--nmo);box-shadow:0 2px 8px rgba(249,115,22,.12)}
[data-theme="light"] .pc.thw {background:#f2f6ff;border-color:rgba(59,130,246,.4);
                               border-left-color:var(--hw); box-shadow:0 2px 8px rgba(59,130,246,.12)}
[data-theme="light"] .pc.tcr {background:#f8f2ff;border-color:rgba(168,85,247,.4);
                               border-left-color:var(--cr); box-shadow:0 2px 8px rgba(168,85,247,.12)}
[data-theme="light"] .pc.ovd {background:#fff2f2;border-color:rgba(239,68,68,.4);
                               border-left-color:var(--red);box-shadow:0 2px 8px rgba(239,68,68,.12)}

.pc-top{display:flex;flex-wrap:wrap;gap:5px;align-items:center}
.pc-ref{font-size:.95rem;font-weight:700;font-family:monospace;color:var(--pink)}
.pc-cust{font-size:.85rem;font-weight:600;color:var(--text)}
.pc-dates{display:flex;flex-direction:column;gap:3px;margin-top:2px}
.pc-date{font-size:.75rem;color:var(--text);display:flex;gap:6px}
.pc-dl{color:var(--muted);min-width:68px;flex-shrink:0}
.pc-bottom{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:2px}

/* ── Accordion ───────────────────────────────────────────────── */
details.acc{border-top:1px solid var(--border);margin-top:2px}
details.acc summary{font-size:.72rem;color:var(--muted);cursor:pointer;padding:5px 0 3px;
  list-style:none;display:flex;align-items:center;justify-content:space-between;
  user-select:none;text-transform:uppercase;letter-spacing:.04em;font-weight:700}
details.acc summary::after{content:'▼';font-size:.55rem;transition:transform .2s}
details.acc[open] summary::after{transform:rotate(-180deg)}
details.acc summary::-webkit-details-marker{display:none}
details.acc .acc-body{padding:6px 0 2px;font-size:.77rem;color:var(--text);
  white-space:pre-wrap;line-height:1.55;word-break:break-word}

/* ── Badges ──────────────────────────────────────────────────── */
.b{font-size:.68rem;font-weight:700;padding:2px 7px;border-radius:10px;
   text-transform:uppercase;letter-spacing:.04em;white-space:nowrap;cursor:default}
.bl {background:var(--bl-bg);color:var(--bl-col)}
.bo {background:rgba(239,68,68,.2);color:var(--red)}
.bw {background:rgba(245,158,11,.2);color:var(--amber)}
.bg {background:rgba(34,197,94,.17);color:var(--green)}
.bs {background:rgba(239,68,68,.2);color:var(--red)}
.bnmo{background:rgba(249,115,22,.18);color:var(--nmo)}
.bhw {background:rgba(59,130,246,.18);color:var(--hw)}
.bcr {background:rgba(168,85,247,.18);color:var(--cr)}
.bst {background:var(--bst-bg);color:var(--muted)}

/* ── Filter bar ──────────────────────────────────────────────── */
.fb{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;align-items:center}
.fb select{background:var(--card);border:1px solid var(--border);color:var(--text);
           padding:6px 10px;border-radius:6px;font-size:.78rem;cursor:pointer}
.fb select:focus{outline:none;border-color:var(--pink)}
.fb-reset{background:none;border:1px solid var(--border);color:var(--muted);
          padding:6px 12px;border-radius:6px;font-size:.76rem;cursor:pointer}
.fb-reset:hover{border-color:var(--pink);color:var(--pink)}
.fb label{font-size:.73rem;color:var(--muted)}

/* ── Jobs table ──────────────────────────────────────────────── */
.tbl-wrap{overflow-x:auto;border-radius:var(--r);border:1px solid var(--border)}
.band-row td{padding:7px 12px;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em}
.band-ovd td{background:rgba(239,68,68,.14);color:var(--red)}
.band-tw  td{background:rgba(245,158,11,.12);color:var(--amber)}
.band-n2w td{background:rgba(59,130,246,.10);color:#80b0ff}
[data-theme="light"] .band-n2w td{color:#2860c0}
.band-lt  td{background:var(--band-lt-bg);color:var(--muted)}
.band-un  td{background:var(--band-un-bg);color:var(--muted);font-style:italic}
table{width:100%;border-collapse:collapse}
th{padding:9px 11px;text-align:left;font-size:.7rem;text-transform:uppercase;
   letter-spacing:.05em;color:var(--muted);background:var(--bg2);
   border-bottom:1px solid var(--border);white-space:nowrap;
   cursor:pointer;user-select:none;position:sticky;top:43px}
th:hover{color:var(--text)}
th.sa::after{content:' ↑';color:var(--pink)}
th.sd::after{content:' ↓';color:var(--pink)}
td{padding:9px 11px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top;font-size:.82rem;color:var(--text)}
[data-theme="light"] td{border-bottom:1px solid var(--border)}
tr:hover td{background:var(--row-hover)}
tr.rnmo td:first-child{border-left:3px solid var(--nmo)}
tr.rhw  td:first-child{border-left:3px solid var(--hw)}
tr.rcr  td:first-child{border-left:3px solid var(--cr)}
.rc{font-family:monospace;color:var(--pink);font-weight:700;white-space:nowrap}
.dc{white-space:nowrap;font-weight:600}
.ovdt{color:var(--red)}.ambt{color:var(--amber)}.okt{color:var(--green)}.mut{color:var(--muted)}

/* ── Detail rows ─────────────────────────────────────────────── */
.detail-row td{padding:0;background:var(--bg)!important}
.detail-pane{padding:12px 14px 14px;display:flex;gap:20px;flex-wrap:wrap;
             border-top:1px solid var(--border)}
.detail-section{flex:1;min-width:220px}
.detail-lbl{font-size:.68rem;color:var(--muted);text-transform:uppercase;
            letter-spacing:.06em;display:block;margin-bottom:5px;font-weight:700}
.detail-text{font-size:.77rem;color:var(--text);white-space:pre-wrap;
             line-height:1.55;word-break:break-word}
.exp-btn{background:none;border:1px solid var(--border);color:var(--muted);
         cursor:pointer;font-size:.68rem;padding:2px 8px;border-radius:4px;transition:all .15s}
.exp-btn:hover,.exp-btn.open{border-color:var(--pink);color:var(--pink)}

/* ── Completed / misc ────────────────────────────────────────── */
.empty{text-align:center;padding:36px;color:var(--muted);font-size:.88rem}
.comp-wrap{overflow-x:auto;border-radius:var(--r);border:1px solid var(--border)}
.toggle-btn{margin-left:8px;background:none;border:1px solid var(--border);color:var(--muted);
            padding:3px 10px;border-radius:6px;font-size:.72rem;cursor:pointer}
.toggle-btn:hover{border-color:var(--pink);color:var(--pink)}

/* ── Category toggle ─────────────────────────────────────────── */
.cat-toggle{display:flex;gap:4px;margin-left:auto}
.cat-btn{background:none;border:1px solid var(--border);color:var(--muted);
         padding:4px 14px;border-radius:6px;font-size:.72rem;font-weight:700;cursor:pointer;
         transition:all .15s}
.cat-btn.active{background:var(--pink);border-color:var(--pink);color:#fff}
.cat-btn:hover:not(.active){border-color:var(--pink);color:var(--pink)}

/* ── Changelog ───────────────────────────────────────────────── */
.cl-empty{background:var(--card);border:1px solid var(--border);border-radius:var(--r);
          padding:24px;text-align:center;color:var(--muted);font-size:.85rem}
.cl-list{display:flex;flex-direction:column;gap:0}
.cl-item{display:flex;gap:20px;padding:20px 0;border-bottom:1px solid var(--border)}
.cl-item:last-child{border-bottom:none}
.cl-date{min-width:100px;flex-shrink:0;font-size:.72rem;color:var(--muted);
         padding-top:2px;font-weight:600;text-align:right}
.cl-dot{width:10px;height:10px;border-radius:50%;background:var(--pink);
        flex-shrink:0;margin-top:5px;box-shadow:0 0 0 3px rgba(233,30,140,.15)}
.cl-body{flex:1}
.cl-title{font-size:.9rem;font-weight:700;color:var(--text);margin-bottom:5px}
.cl-desc{font-size:.8rem;color:var(--muted);line-height:1.6;white-space:pre-wrap}

footer{text-align:center;padding:24px 16px;color:var(--muted);font-size:.72rem;
       border-top:1px solid var(--border);margin-top:20px}

@media(max-width:600px){
  .pg{grid-template-columns:1fr}
  .hdr-ts{margin-left:0;width:100%;text-align:left}
  th,td{padding:7px 8px}
  .nav a{padding:10px 14px;font-size:.72rem}
  .detail-pane{flex-direction:column;gap:12px}
}
</style>
</head>
<body>

<!-- Auth overlay -->
<div id="auth-overlay">
  <div id="auth-box">
    <div id="auth-avatar">%%INITIAL%%</div>
    <div id="auth-name">%%MEMBER%%</div>
    <div id="auth-sub">Enter your password to view your planner</div>
    <input type="password" id="auth-pw-input" placeholder="Your password" autocomplete="current-password">
    <button id="auth-pw-submit">Sign In</button>
    <div id="auth-pw-err" style="display:none"></div>
  </div>
</div>

<!-- Loading overlay (data fetch after auth) -->
<div id="load-overlay">
  <div class="load-spin"></div>
  <div id="load-msg">Loading your jobs&hellip;</div>
</div>

<header class="hdr">
  <div class="hdr-inner">
    <a id="back-btn" class="back-btn visible" href="index.html">&#8592; All Members</a>
    <div class="avatar-wrap" title="Click to change your accent colour">
      <div class="avatar" id="member-avatar">%%INITIAL%%</div>
      <input type="color" id="avatar-color-picker">
    </div>
    <div>
      <div class="hdr-name">%%MEMBER%%</div>
      <div class="hdr-sub">Software Customisations &mdash; Flowbird / Arrive</div>
    </div>
    <div class="hdr-ts">
      <span id="current-time" class="cur-time">--:--</span>
      <span class="upd-time" id="data-fetched-ts"></span>
      <small>Updates hourly</small>
    </div>
    <button id="theme-btn" class="theme-btn" onclick="toggleTheme()">&#9728; Light</button>
  </div>
</header>

<nav class="nav">
  <div class="nav-inner">
    <div class="nav-links">
      <a href="#priorities" class="act">Priorities</a>
      <a href="#jobs">All Jobs</a>
      <a href="#completed">Completed</a>
      <a href="#changelog">What's New</a>
    </div>
    <div class="nav-user">
      <span id="nav-user-email"></span>
      <button class="nav-signout" id="nav-signout-btn" style="display:none">Sign out</button>
    </div>
  </div>
</nav>

<main>
  <section id="priorities">
    <div class="sec-hdr"><h2>Your Priorities</h2><span class="sec-cnt" id="p-cnt">0</span></div>
    <div class="sec-sub">Jobs due in the next 2 weeks, plus anything overdue</div>
    <div id="priorities-content"></div>
  </section>

  <section id="jobs">
    <div class="sec-hdr"><h2>All Active Jobs</h2><span class="sec-cnt" id="j-cnt">0</span></div>
    <div class="sec-sub">Your full pipeline &mdash; filter and sort to focus</div>
    <div class="fb">
      <label>Type</label>
      <select id="f-type">
        <option value="all">All Types</option>
        <option value="nmo">New Machine Order</option>
        <option value="hw">Hardware Upgrade</option>
        <option value="cr">Change Request</option>
      </select>
      <label>Status</label>
      <select id="f-status"><option value="all">All Statuses</option></select>
      <label>Period</label>
      <select id="f-period">
        <option value="all">All Periods</option>
        <option value="overdue">Overdue</option>
        <option value="thisweek">This Week</option>
        <option value="next2w">Next 2 Weeks</option>
        <option value="later">Later</option>
        <option value="unscheduled">Unscheduled</option>
      </select>
      <button class="fb-reset" id="f-reset">Clear filters</button>
    </div>
    <div id="jobs-table"></div>
  </section>

  <section id="unassigned">
    <div class="sec-hdr">
      <h2>Unassigned Jobs</h2><span class="sec-cnt" id="u-cnt">0</span>
      <div class="cat-toggle">
        <button id="u-cwt-btn" class="cat-btn" onclick="switchCat('CWT')">CWT</button>
        <button id="u-neops-btn" class="cat-btn" onclick="switchCat('NEOPS')">NEOPS</button>
      </div>
    </div>
    <div class="sec-sub">Jobs not yet assigned &mdash; see what&rsquo;s coming down the pipeline</div>
    <div id="unassigned-table"></div>
  </section>

  <section id="completed">
    <div class="sec-hdr">
      <h2>Completed Jobs</h2>
      <span class="sec-cnt" id="c-cnt">0</span>
      <button class="toggle-btn" id="comp-toggle" onclick="toggleCompleted()">Show &#9660;</button>
    </div>
    <div class="sec-sub">All shipped work &mdash; newest first</div>
    <div id="comp-table" style="display:none"></div>
  </section>

  <section id="changelog">
    <div class="sec-hdr"><h2>What's New</h2><span class="sec-cnt" id="cl-cnt">0</span></div>
    <div class="sec-sub">Updates and changes to your planner</div>
    <div id="changelog-content"></div>
  </section>
</main>

<footer>
  Daily Planner &mdash; Software Customisations &mdash; Flowbird / Arrive &nbsp;&middot;&nbsp;
  Updates hourly
</footer>

<script>
// ── Theme ─────────────────────────────────────────────────────────────────────
(function(){
  var t=localStorage.getItem('planner_theme')||'dark';
  document.documentElement.setAttribute('data-theme',t);
  _setThemeBtn(t);
})();
function toggleTheme(){
  var t=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';
  document.documentElement.setAttribute('data-theme',t);
  localStorage.setItem('planner_theme',t);
  _setThemeBtn(t);
}
function _setThemeBtn(t){
  var b=document.getElementById('theme-btn');
  if(b)b.innerHTML=t==='dark'?'&#9728; Light':'&#9790; Dark';
}

// ── Clock ─────────────────────────────────────────────────────────────────────
function _tick(){
  var el=document.getElementById('current-time');
  if(!el)return;
  var d=new Date();
  el.textContent=String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0');
}
_tick();
setInterval(_tick,30000);

// ── Accent colour ─────────────────────────────────────────────────────────────
(function(){
  var KEY='planner_avc_%%MEMBER%%';
  var c=localStorage.getItem(KEY)||'#e91e8c';
  function _apply(col){
    document.querySelectorAll('.avatar,#auth-avatar').forEach(function(a){a.style.background=col;});
    document.documentElement.style.setProperty('--pink',col);
  }
  _apply(c);
  var pk=document.getElementById('avatar-color-picker');
  if(pk){pk.value=c;pk.addEventListener('input',function(){_apply(pk.value);localStorage.setItem(KEY,pk.value);});}
})();

// ── Data (populated after auth + fetch) ───────────────────────────────────────
var MEMBER_CATEGORY = '%%MEMBER_CATEGORY%%';
var JOBS = [], COMPLETED = [], UNASSIGNED_CWT = [], UNASSIGNED_NEOPS = [];
var LH = %%LH_JSON%%;
const CAP2W = %%CAP2W%%;
var CHANGELOG = %%CHANGELOG_JSON%%;

// ── Auth & data loading ───────────────────────────────────────────────────────
var _authOverlay = document.getElementById('auth-overlay');
var _loadOverlay = document.getElementById('load-overlay');
var _navSignout  = document.getElementById('nav-signout-btn');
var MEMBER_PW_HASH = '%%MEMBER_PW_HASH%%';
var _blobKey = 'm';

async function _sha256(s){
  var b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));
  return Array.from(new Uint8Array(b)).map(function(x){return x.toString(16).padStart(2,'0')}).join('');
}
function _b64ToArr(b64){
  var raw=atob(b64),arr=new Uint8Array(raw.length);
  for(var i=0;i<raw.length;i++)arr[i]=raw.charCodeAt(i);
  return arr;
}
async function _decryptBlob(blob,pw){
  try{
    var km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),{name:'PBKDF2'},false,['deriveKey']);
    var key=await crypto.subtle.deriveKey(
      {name:'PBKDF2',salt:_b64ToArr(blob.s),iterations:100000,hash:'SHA-256'},
      km,{name:'AES-GCM',length:256},false,['decrypt']);
    var pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:_b64ToArr(blob.i)},key,_b64ToArr(blob.c));
    return JSON.parse(new TextDecoder().decode(pt));
  }catch(e){return null;}
}
function _clearAuth(){localStorage.removeItem('fp_auth');localStorage.removeItem('fp_pw');localStorage.removeItem('fp_blob');}
var _MAX_ATTEMPTS=5,_LOCKOUT_MS=120000;
function _isLocked(){var t=sessionStorage.getItem('fp_locked');if(!t)return false;if(Date.now()-parseInt(t)<_LOCKOUT_MS)return true;sessionStorage.removeItem('fp_locked');sessionStorage.removeItem('fp_fails');return false;}
function _lockoutSecs(){return Math.ceil((_LOCKOUT_MS-(Date.now()-parseInt(sessionStorage.getItem('fp_locked')||'0')))/1000);}
function _recordFail(){var n=parseInt(sessionStorage.getItem('fp_fails')||'0')+1;sessionStorage.setItem('fp_fails',String(n));if(n>=_MAX_ATTEMPTS)sessionStorage.setItem('fp_locked',String(Date.now()));return n;}
function _showErr(msg){var e=document.getElementById('auth-pw-err');e.textContent=msg;e.style.display='block';}
function _startLockout(){
  var inp=document.getElementById('auth-pw-input');
  var btn=document.getElementById('auth-pw-submit');
  inp.disabled=true;btn.disabled=true;btn.style.opacity='.5';
  (function tick(){
    if(!_isLocked()){inp.disabled=false;btn.disabled=false;btn.style.opacity='';document.getElementById('auth-pw-err').style.display='none';sessionStorage.removeItem('fp_fails');return;}
    _showErr('Too many attempts — try again in '+_lockoutSecs()+'s');
    setTimeout(tick,1000);
  })();
}
async function _checkAuth(){
  if(_isLocked()){_authOverlay.style.display='flex';_startLockout();return;}
  var stored_hash=localStorage.getItem('fp_auth');
  var stored_pw=localStorage.getItem('fp_pw');
  if(stored_hash&&stored_pw){
    _blobKey=(stored_hash===MEMBER_PW_HASH)?'m':(localStorage.getItem('fp_blob')||'m');
    _authOverlay.style.display='none';
    _navSignout.style.display='inline-block';
    _loadData(stored_pw);
    return;
  }
  _authOverlay.style.display='flex';
}
document.getElementById('auth-pw-input').addEventListener('keydown',function(e){
  if(e.key==='Enter')document.getElementById('auth-pw-submit').click();
});
document.getElementById('auth-pw-submit').addEventListener('click',async function(){
  if(_isLocked()){_startLockout();return;}
  var pw=document.getElementById('auth-pw-input').value;
  var h=await _sha256(pw);
  if(h===MEMBER_PW_HASH){
    sessionStorage.removeItem('fp_fails');sessionStorage.removeItem('fp_locked');
    _blobKey='m';
    localStorage.setItem('fp_auth',h);localStorage.setItem('fp_pw',pw);localStorage.setItem('fp_blob','m');
    _authOverlay.style.display='none';
    _navSignout.style.display='inline-block';
    _loadData(pw);
    return;
  }
  // Silently try master blob — no hash exposed in source
  _loadOverlay.style.display='flex';
  fetch('data/%%MEMBER_LOWER%%.json')
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})
  .then(async function(enc){
    if(enc&&enc.v===1){
      var data=await _decryptBlob(enc.x,pw);
      if(data){
        sessionStorage.removeItem('fp_fails');sessionStorage.removeItem('fp_locked');
        _blobKey='x';
        localStorage.setItem('fp_auth',h);localStorage.setItem('fp_pw',pw);localStorage.setItem('fp_blob','x');
        _authOverlay.style.display='none';
        _navSignout.style.display='inline-block';
        _loadOverlay.style.display='none';
        _afterLoad(data);
        return;
      }
    }
    _loadOverlay.style.display='none';
    var n=_recordFail();
    if(_isLocked()){_startLockout();}
    else{_showErr('Incorrect password — '+(_MAX_ATTEMPTS-n)+' attempt'+(_MAX_ATTEMPTS-n===1?'':'s')+' remaining');}
    document.getElementById('auth-pw-input').value='';
  })
  .catch(function(){
    _loadOverlay.style.display='none';
    var n=_recordFail();
    if(_isLocked()){_startLockout();}else{_showErr('Incorrect password');}
    document.getElementById('auth-pw-input').value='';
  });
});
_navSignout.addEventListener('click',function(){_clearAuth();location.reload();});
function _afterLoad(data){
  JOBS             = data.jobs             || [];
  COMPLETED        = data.completed        || [];
  UNASSIGNED_CWT   = data.unassigned_cwt   || [];
  UNASSIGNED_NEOPS = data.unassigned_neops || [];
  _loadOverlay.style.display='none';
  var _ts=document.getElementById('data-fetched-ts');
  if(_ts)_ts.textContent='Updated '+(data.generated_at||'--:--');
  _populateStatusFilter();
  renderPriorities();
  renderJobs();
  renderUnassigned();
  renderCompleted();
  renderChangelog();
}
function _loadData(pw){
  _loadOverlay.style.display='flex';
  fetch('data/%%MEMBER_LOWER%%.json')
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})
  .then(async function(enc){
    var data=null;
    if(enc&&enc.v===1){
      data=await _decryptBlob(enc[_blobKey],pw);
      if(!data){_clearAuth();_loadOverlay.style.display='none';_authOverlay.style.display='flex';return;}
    }else{data=enc;}
    _afterLoad(data);
  })
  .catch(function(err){
    _loadOverlay.style.display='none';
    document.getElementById('load-msg').textContent='Failed to load data — please refresh.';
    console.error(err);
  });
}
window.addEventListener('load',_checkAuth);

// ── Render helpers ────────────────────────────────────────────────────────────
function esc(s){
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function daysLabel(j){
  if(j.unscheduled||j.days_left===null||j.days_left===undefined) return '<span class="mut">No date</span>';
  if(j.overdue) return '<span class="ovdt">'+Math.abs(j.days_left)+'d overdue</span>';
  if(j.days_left===0) return '<span class="ambt">Due today</span>';
  if(j.days_left<=5)  return '<span class="ambt">'+j.days_left+'d left</span>';
  return '<span class="okt">'+j.days_left+'d</span>';
}
function typeBadge(t){
  if(t==='New Machine Order') return '<span class="b bnmo" title="New Machine Order">NMO</span>';
  if(t==='Hardware Upgrade')  return '<span class="b bhw" title="Hardware Upgrade">HW</span>';
  return '<span class="b bcr" title="Change Request">CR</span>';
}
function levelBadge(l){
  if(!l) return '<span class="mut">&mdash;</span>';
  return '<span class="b bl">'+esc(l)+' &middot; '+(LH[l.toUpperCase()]||'?')+'h</span>';
}
function getBand(j){
  if(j.unscheduled||j.days_left===null||j.days_left===undefined) return 'unscheduled';
  if(j.overdue)      return 'overdue';
  if(j.days_left<7)  return 'thisweek';
  if(j.days_left<14) return 'next2w';
  return 'later';
}
function rowCls(j){
  if(j.order_type==='New Machine Order') return 'rnmo';
  if(j.order_type==='Hardware Upgrade')  return 'rhw';
  return 'rcr';
}

// ── Priorities ────────────────────────────────────────────────────────────────
function renderPriorities(){
  const pjobs=JOBS.filter(j=>!j.unscheduled&&(j.overdue||(j.days_left!==null&&j.days_left<14)))
    .sort((a,b)=>{
      if(a.overdue&&!b.overdue) return -1;
      if(!a.overdue&&b.overdue) return 1;
      return (a.days_left!==null?a.days_left:9999)-(b.days_left!==null?b.days_left:9999);
    });
  document.getElementById('p-cnt').textContent=pjobs.length;
  const comm=pjobs.reduce((s,j)=>(j.status||'').toLowerCase()==='queued'?s:s+(LH[(j.level||'').toUpperCase()]||0),0);
  const pct=Math.min(100,Math.round(comm/CAP2W*100));
  const fc=pct>=100?'var(--red)':pct>=70?'var(--amber)':'var(--green)';
  const free=Math.max(0,CAP2W-comm);
  let html='<div class="cap"><div class="cap-lbl">Capacity &mdash; Next 2 Weeks</div>';
  html+='<div class="cap-bg"><div class="cap-fill" style="width:'+pct+'%;background:'+fc+'"></div></div>';
  html+='<div class="cap-txt"><strong>'+comm+'h</strong> committed of <strong>'+CAP2W+'h</strong> &mdash; <strong style="color:'+fc+'">'+free+'h free</strong></div></div>';
  if(!pjobs.length){
    html+="<div class='p-empty'>&#10003; Nothing due in the next 2 weeks &mdash; you are on top of it!</div>";
  } else {
    html+='<div class="pg">';
    pjobs.forEach(j=>{
      const tc=j.order_type==='New Machine Order'?'tnmo':j.order_type==='Hardware Upgrade'?'thw':'tcr';
      const oc=j.overdue?' ovd':'';
      const sla=j.sla_breach?'<span class="b bs">&#9888; SLA</span>':'';
      const dlRow=j.date_logged?'<div class="pc-date"><span class="pc-dl">Logged</span>'+esc(j.date_logged)+'</div>':'';
      const rdRow=j.requested_date?'<div class="pc-date"><span class="pc-dl">Requested</span>'+esc(j.requested_date)+'</div>':'';
      const glRow='<div class="pc-date"><span class="pc-dl">Go Live</span>'+(j.due_date?esc(j.due_date):'TBC')+'</div>';
      const accCom=j.comments?'<details class="acc"><summary>Latest Action</summary><div class="acc-body">'+esc(j.comments)+'</div></details>':'';
      const accSal=j.sales_comments?'<details class="acc"><summary>Sales Notes</summary><div class="acc-body">'+esc(j.sales_comments)+'</div></details>':'';
      html+='<div class="pc '+tc+oc+'">'+
        '<div class="pc-top">'+typeBadge(j.order_type)+' '+levelBadge(j.level)+' '+sla+'</div>'+
        '<div class="pc-ref">'+esc(j.reference)+'</div>'+
        '<div class="pc-cust">'+esc(j.customer)+'</div>'+
        '<div class="pc-dates">'+dlRow+rdRow+glRow+'</div>'+
        '<div class="pc-bottom">'+daysLabel(j)+' <span class="b bst">'+esc(j.status)+'</span></div>'+
        accCom+accSal+'</div>';
    });
    html+='</div>';
  }
  document.getElementById('priorities-content').innerHTML=html;
}

// ── Jobs table ────────────────────────────────────────────────────────────────
let sCol='due_date_iso',sDir=1;
const BANDS=['overdue','thisweek','next2w','later','unscheduled'];
const BLBL={overdue:'&#9888; Overdue',thisweek:'This Week',next2w:'Next 2 Weeks',later:'Later',unscheduled:'Unscheduled'};
const BCL={overdue:'band-ovd',thisweek:'band-tw',next2w:'band-n2w',later:'band-lt',unscheduled:'band-un'};

function filteredJobs(){
  const ft=document.getElementById('f-type').value;
  const fs=document.getElementById('f-status').value;
  const fp=document.getElementById('f-period').value;
  return JOBS.filter(j=>{
    if(ft!=='all'){
      if(ft==='nmo'&&j.order_type!=='New Machine Order') return false;
      if(ft==='hw' &&j.order_type!=='Hardware Upgrade')  return false;
      if(ft==='cr' &&j.order_type!=='Change Request')    return false;
    }
    if(fs!=='all'&&(j.status||'').toLowerCase()!==fs) return false;
    if(fp!=='all'&&getBand(j)!==fp) return false;
    return true;
  });
}
function sortedJobs(jobs){
  return [...jobs].sort((a,b)=>{
    let av=a[sCol]||'',bv=b[sCol]||'';
    if(!av&&bv) return 1; if(av&&!bv) return -1;
    if(sCol==='days_left'){av=a.days_left!==null?a.days_left:9999;bv=b.days_left!==null?b.days_left:9999;}
    if(sCol==='level'){const O={XS:1,S:2,M:3,L:4,XL:5};av=O[(a.level||'').toUpperCase()]||0;bv=O[(b.level||'').toUpperCase()]||0;}
    return av<bv?-sDir:av>bv?sDir:0;
  });
}
function jobRow(j){
  const slaD=j.sla_deadline||j.effective_deadline||'';
  const slaCell=slaD?(j.sla_breach?'<span class="ovdt">&#9888; '+esc(slaD)+'</span>':'<span class="okt">'+esc(slaD)+'</span>'):'<span class="mut">N/A</span>';
  const loc=j.location?'<br><span style="font-size:.72rem;color:var(--muted)">'+esc(j.location)+'</span>':'';
  const hasDetail=!!(j.comments||j.sales_comments);
  const expBtn=hasDetail?'<button class="exp-btn">&#9660;</button>':'';
  const mainRow='<tr class="'+rowCls(j)+'">'+
    '<td class="rc">'+esc(j.reference)+'</td>'+
    '<td>'+typeBadge(j.order_type)+'</td>'+
    '<td>'+esc(j.customer)+loc+'</td>'+
    '<td>'+levelBadge(j.level)+'</td>'+
    '<td>'+(j.due_date?esc(j.due_date):'<span class="mut">&mdash;</span>')+'</td>'+
    '<td class="dc">'+daysLabel(j)+'</td>'+
    '<td><span class="b bst">'+esc(j.status)+'</span></td>'+
    '<td class="dc" style="font-size:.75rem">'+slaCell+'</td>'+
    '<td>'+expBtn+'</td>'+
  '</tr>';
  if(!hasDetail) return mainRow;
  const secs=[];
  if(j.comments) secs.push('<div class="detail-section"><span class="detail-lbl">Latest Action</span><span class="detail-text">'+esc(j.comments)+'</span></div>');
  if(j.sales_comments) secs.push('<div class="detail-section"><span class="detail-lbl">Sales Notes</span><span class="detail-text">'+esc(j.sales_comments)+'</span></div>');
  return mainRow+'<tr class="detail-row" style="display:none"><td colspan="9"><div class="detail-pane">'+secs.join('')+'</div></td></tr>';
}
function renderJobs(){
  const fj=filteredJobs();
  const sj=sortedJobs(fj);
  const isGrouped=(document.getElementById('f-type').value==='all'&&
    document.getElementById('f-status').value==='all'&&
    document.getElementById('f-period').value==='all'&&sCol==='due_date_iso');
  document.getElementById('j-cnt').textContent=fj.length;
  const el=document.getElementById('jobs-table');
  if(!sj.length){el.innerHTML='<div class="empty">No jobs match the current filters.</div>';return;}
  const thead='<thead><tr>'+
    ['reference','order_type','customer','level','due_date_iso','days_left','status','','']
    .map((c,i)=>{
      const labels=['Reference','Type','Customer','Level','Due Date','Days','Status','SLA Deadline',''];
      const cls=c===sCol?(sDir===1?' class="sa"':' class="sd"'):'';
      const dc=c?(' data-col="'+c+'"'):'';
      return '<th'+cls+dc+'>'+labels[i]+'</th>';
    }).join('')+'</tr></thead>';
  let body='<tbody>';
  if(isGrouped){
    const grp={};BANDS.forEach(b=>grp[b]=[]);
    sj.forEach(j=>grp[getBand(j)].push(j));
    BANDS.forEach(b=>{
      if(!grp[b].length) return;
      body+='<tr class="band-row '+BCL[b]+'"><td colspan="9">'+BLBL[b]+' ('+grp[b].length+')</td></tr>';
      body+=grp[b].map(jobRow).join('');
    });
  } else {
    body+=sj.map(jobRow).join('');
  }
  body+='</tbody>';
  el.innerHTML='<div class="tbl-wrap"><table>'+thead+body+'</table></div>';
  el.querySelectorAll('th[data-col]').forEach(th=>{
    th.addEventListener('click',()=>{
      if(sCol===th.dataset.col) sDir*=-1;
      else{sCol=th.dataset.col;sDir=1;}
      renderJobs();
    });
  });
  el.querySelector('table').addEventListener('click',function(e){
    const btn=e.target.closest('.exp-btn');
    if(!btn) return;
    const mainRow=btn.closest('tr');
    const dRow=mainRow.nextElementSibling;
    if(dRow&&dRow.classList.contains('detail-row')){
      const open=dRow.style.display!=='none';
      dRow.style.display=open?'none':'table-row';
      btn.innerHTML=open?'&#9660;':'&#9650;';
      btn.classList.toggle('open',!open);
    }
  });
}

// ── Unassigned jobs ───────────────────────────────────────────────────────────
var _activeCat = MEMBER_CATEGORY;
(function(){
  var cwtBtn   = document.getElementById('u-cwt-btn');
  var neopsBtn = document.getElementById('u-neops-btn');
  if(cwtBtn)   cwtBtn.classList.toggle('active',   _activeCat==='CWT');
  if(neopsBtn) neopsBtn.classList.toggle('active', _activeCat==='NEOPS');
})();

function switchCat(cat){
  _activeCat = cat;
  document.getElementById('u-cwt-btn').classList.toggle('active',   cat==='CWT');
  document.getElementById('u-neops-btn').classList.toggle('active', cat==='NEOPS');
  renderUnassigned();
}

function renderUnassigned(){
  var jobs = _activeCat==='CWT' ? UNASSIGNED_CWT : UNASSIGNED_NEOPS;
  document.getElementById('u-cnt').textContent = jobs.length;
  var el = document.getElementById('unassigned-table');
  if(!jobs.length){
    el.innerHTML='<div class="empty">No unassigned '+_activeCat+' jobs right now.</div>';
    return;
  }
  var sorted=[...jobs].sort((a,b)=>{
    var av=a.due_date_iso||'',bv=b.due_date_iso||'';
    if(!av&&bv) return 1; if(av&&!bv) return -1;
    return av<bv?-1:av>bv?1:0;
  });
  var html='<div class="tbl-wrap"><table><thead><tr>'+
    '<th>Reference</th><th>Type</th><th>Customer</th><th>Level</th>'+
    '<th>Due Date</th><th>Days</th><th>Status</th></tr></thead><tbody>';
  sorted.forEach(function(j){
    var loc=j.location?'<br><span style="font-size:.72rem;color:var(--muted)">'+esc(j.location)+'</span>':'';
    html+='<tr class="'+rowCls(j)+'">'+
      '<td class="rc">'+esc(j.reference)+'</td>'+
      '<td>'+typeBadge(j.order_type)+'</td>'+
      '<td>'+esc(j.customer)+loc+'</td>'+
      '<td>'+levelBadge(j.level)+'</td>'+
      '<td>'+(j.due_date?esc(j.due_date):'<span class="mut">&mdash;</span>')+'</td>'+
      '<td class="dc">'+daysLabel(j)+'</td>'+
      '<td><span class="b bst">'+esc(j.status)+'</span></td>'+
      '</tr>';
  });
  html+='</tbody></table></div>';
  el.innerHTML=html;
}

// ── Completed ─────────────────────────────────────────────────────────────────
function toggleCompleted(){
  var el=document.getElementById('comp-table');
  var btn=document.getElementById('comp-toggle');
  var vis=el.style.display!=='none';
  el.style.display=vis?'none':'block';
  btn.innerHTML=vis?'Show &#9660;':'Hide &#9650;';
}
function renderCompleted(){
  document.getElementById('c-cnt').textContent=COMPLETED.length;
  const el=document.getElementById('comp-table');
  if(!COMPLETED.length){el.innerHTML='<div class="empty">No completed jobs yet.</div>';return;}
  const sorted=[...COMPLETED].sort((a,b)=>(b.due_date||'').localeCompare(a.due_date||''));
  let html='<div class="comp-wrap"><table><thead><tr><th>Reference</th><th>Type</th><th>Customer</th><th>Level</th><th>Completed</th></tr></thead><tbody>';
  sorted.forEach(j=>{
    html+='<tr>'+
      '<td class="rc">'+esc(j.reference)+'</td>'+
      '<td>'+typeBadge(j.order_type)+'</td>'+
      '<td>'+esc(j.customer)+'</td>'+
      '<td>'+levelBadge(j.level)+'</td>'+
      '<td>'+(j.due_date?esc(j.due_date):'<span class="mut">&mdash;</span>')+'</td>'+
    '</tr>';
  });
  html+='</tbody></table></div>';
  el.innerHTML=html;
}

// ── Changelog ─────────────────────────────────────────────────────────────────
function renderChangelog(){
  document.getElementById('cl-cnt').textContent=CHANGELOG.length;
  const el=document.getElementById('changelog-content');
  if(!CHANGELOG.length){
    el.innerHTML='<div class="cl-empty">No updates yet &mdash; check back here when changes are made to your planner.</div>';
    return;
  }
  let html='<div class="cl-list">';
  CHANGELOG.forEach(function(c){
    html+='<div class="cl-item">'+
      '<div class="cl-date">'+esc(c.date)+'</div>'+
      '<div class="cl-dot"></div>'+
      '<div class="cl-body">'+
        '<div class="cl-title">'+esc(c.title)+'</div>'+
        (c.body?'<div class="cl-desc">'+esc(c.body)+'</div>':'')+
      '</div>'+
    '</div>';
  });
  html+='</div>';
  el.innerHTML=html;
}

// ── Status filter ─────────────────────────────────────────────────────────────
function _populateStatusFilter(){
  const statuses=[...new Set(JOBS.map(j=>j.status).filter(Boolean))].sort();
  const sel=document.getElementById('f-status');
  sel.innerHTML='<option value="all">All Statuses</option>';
  statuses.forEach(s=>{const o=document.createElement('option');o.value=s.toLowerCase();o.textContent=s;sel.appendChild(o);});
}
['f-type','f-status','f-period'].forEach(id=>document.getElementById(id).addEventListener('change',renderJobs));
document.getElementById('f-reset').addEventListener('click',()=>{
  document.getElementById('f-type').value='all';
  document.getElementById('f-status').value='all';
  document.getElementById('f-period').value='all';
  sCol='due_date_iso';sDir=1;renderJobs();
});

// ── Nav scroll highlight ──────────────────────────────────────────────────────
const _secs=['priorities','jobs','completed','changelog'],_nl={};
_secs.forEach(id=>{_nl[id]=document.querySelector('.nav a[href="#'+id+'"]');});
window.addEventListener('scroll',()=>{
  let cur=_secs[0];
  _secs.forEach(id=>{const el=document.getElementById(id);if(el&&el.getBoundingClientRect().top<=80)cur=id;});
  _secs.forEach(id=>{if(_nl[id])_nl[id].classList.toggle('act',id===cur);});
},{passive:true});
</script>
</body>
</html>"""


# ── Index page template ───────────────────────────────────────────────────────

INDEX_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Team Planner &mdash; Software Customisations</title>
<style>
:root{--bg:#0e0e20;--bg2:#13132e;--text:#d8d8f0;--muted:#8888c0;--pink:#e91e8c;--border:#26265a;
      --surface:#161927;--green:#22c55e;--green-soft:rgba(34,197,94,.12);--pink-soft:rgba(233,30,140,.1);--pink-soft2:rgba(233,30,140,.18)}
[data-theme="light"]{--bg:#f0f0f8;--bg2:#ffffff;--text:#1a1a3a;--muted:#5050a0;--border:#d0d0e8;
                     --surface:#ffffff;--pink-soft:rgba(233,30,140,.07);--pink-soft2:rgba(233,30,140,.14);--green-soft:rgba(34,197,94,.1)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}

/* ── Top bar ── */
.topbar{display:flex;align-items:center;justify-content:space-between;padding:16px 24px;border-bottom:1px solid var(--border)}
.topbar-title{font-size:1.05rem;font-weight:700}
.topbar-sub{font-size:.75rem;color:var(--muted);margin-top:1px}
.theme-btn{background:none;border:1px solid var(--border);color:var(--muted);padding:5px 11px;border-radius:6px;font-size:.74rem;cursor:pointer}
.theme-btn:hover{border-color:var(--pink);color:var(--pink)}

/* ── Tabs ── */
.tabs{display:flex;gap:0;border-bottom:1px solid var(--border);padding:0 24px}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;color:var(--muted);
         padding:12px 18px;font-size:.85rem;font-weight:600;cursor:pointer;transition:all .15s;margin-bottom:-1px}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--pink);border-bottom-color:var(--pink)}

/* ── Team tab ── */
#tab-team{display:flex;flex-direction:column;align-items:center;padding:40px 24px 60px}
.links{display:flex;flex-wrap:wrap;gap:12px;justify-content:center;max-width:520px;margin-bottom:32px}
.member-link{display:flex;align-items:center;gap:12px;background:var(--bg2);border:1px solid var(--border);
             border-radius:10px;padding:14px 22px;text-decoration:none;color:var(--text);transition:all .15s;min-width:150px}
.member-link:hover{border-color:var(--pink);background:var(--pink-soft2)}
.mi{width:34px;height:34px;background:var(--pink);border-radius:50%;display:flex;align-items:center;
    justify-content:center;font-weight:700;font-size:.95rem;color:#fff;flex-shrink:0}
.mn{font-weight:600;font-size:.95rem}
.team-footer{color:var(--muted);font-size:.72rem;text-align:center}

/* ── About tab ── */
#tab-about{display:none;padding:40px 24px 60px;max-width:720px;margin:0 auto}
.intro{background:var(--pink-soft2);border:1px solid rgba(233,30,140,.25);border-radius:12px;
       padding:18px 20px;margin-bottom:28px;font-size:14.5px;line-height:1.6}
.intro strong{color:var(--pink)}
.section{margin-bottom:28px}
.section-label{font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--pink);margin-bottom:12px}
.steps{display:flex;flex-direction:column;gap:10px}
.step{display:flex;gap:14px;align-items:flex-start;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.step-num{flex-shrink:0;width:26px;height:26px;background:var(--pink);color:#fff;border-radius:50%;
          display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;margin-top:1px}
.step-body{flex:1}
.step-body strong{font-size:14px;display:block;margin-bottom:3px}
.step-body span{font-size:13px;color:var(--muted)}
.url{font-family:'Courier New',monospace;font-size:12px;background:var(--bg);border:1px solid var(--border);
     border-radius:5px;padding:3px 7px;display:inline-block;margin-top:5px;color:var(--pink);word-break:break-all}
.features{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:500px){.features{grid-template-columns:1fr}}
.feature{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.feature-title{font-size:13px;font-weight:700;margin-bottom:4px}
.feature-desc{font-size:12.5px;color:var(--muted);line-height:1.5}
.badge{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
       padding:2px 7px;border-radius:4px;background:var(--pink-soft);color:var(--pink);display:inline-block;margin-bottom:7px}
.badge.green{background:var(--green-soft);color:var(--green)}
.member-list{display:flex;flex-direction:column;gap:8px}
.member-row{display:flex;align-items:center;gap:12px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:11px 14px}
.member-avatar{width:34px;height:34px;background:var(--pink);color:#fff;border-radius:50%;
               display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0}
.member-avatar.bo{background:#7c3aed}
.member-name{font-size:14px;font-weight:600}
.member-type{font-size:10.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:1px}
.member-link-sm{font-family:'Courier New',monospace;font-size:11.5px;color:var(--pink);text-decoration:none;
                background:var(--pink-soft);padding:4px 9px;border-radius:6px;white-space:nowrap}
.member-link-sm:hover{background:var(--pink-soft2)}
.security{background:var(--green-soft);border:1px solid rgba(34,197,94,.2);border-radius:10px;
          padding:14px 16px;display:flex;gap:12px;align-items:flex-start;font-size:13.5px}
.security-text{line-height:1.5}
.security-text strong{color:var(--green)}
.divider{border:none;border-top:1px solid var(--border);margin:24px 0}

/* ── Changelog tab ── */
#tab-changelog{display:none;padding:36px 24px 60px;max-width:640px;margin:0 auto}
.cl-empty{color:var(--muted);font-size:.88rem;text-align:center;padding:40px 0}
.cl-list{display:flex;flex-direction:column;gap:12px}
.cl-item{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 18px;display:flex;gap:14px;align-items:flex-start}
.cl-date{font-size:11px;font-weight:700;color:var(--pink);white-space:nowrap;padding-top:2px;min-width:72px}
.cl-body{}
.cl-title{font-size:14px;font-weight:700;margin-bottom:3px}
.cl-desc{font-size:13px;color:var(--muted);line-height:1.5}
</style>
</head>
<body>
<div class="topbar">
  <div>
    <div class="topbar-title">&#x2726; Team Planner</div>
    <div class="topbar-sub">Software Customisations &mdash; Flowbird / Arrive</div>
  </div>
  <button class="theme-btn" id="theme-btn" onclick="toggleTheme()">&#9728; Light</button>
</div>

<div class="tabs">
  <button class="tab-btn active" id="btn-team" onclick="showTab('team')">&#128101; Team</button>
  <button class="tab-btn" id="btn-about" onclick="showTab('about')">&#9432; About &amp; Getting Started</button>
  <button class="tab-btn" id="btn-changelog" onclick="showTab('changelog')">&#128203; What's New</button>
</div>

<!-- Team tab -->
<div id="tab-team">
  <div class="links">%%MEMBER_LINKS%%</div>
  <div class="team-footer">Enter your personal password to view your jobs.<br>Data sourced from the team Google Sheet &mdash; refreshes hourly.</div>
</div>

<!-- About tab -->
<div id="tab-about">
  <div class="intro">
    We've built a <strong>personal dashboard</strong> for each of you &mdash; a page you can access from anywhere (phone, home, wherever) that shows your active jobs, what's urgent, and key dates. All data comes directly from the team Google Sheet and refreshes automatically every hour. <strong>No more needing to ask Ross</strong> what's on your plate!
  </div>

  <div class="section">
    <div class="section-label">Getting Started</div>
    <div class="steps">
      <div class="step"><div class="step-num">1</div><div class="step-body"><strong>Get your personal password from Ross</strong><span>Each person has their own unique password &mdash; yours only works on your page. Ask Ross if you don't have it yet.</span></div></div>
      <div class="step"><div class="step-num">2</div><div class="step-body"><strong>Find your personal page in the list below and bookmark it</strong><span>Enter your personal password when prompted &mdash; your browser remembers it after that.</span><div class="url">https://rosscox-blip.github.io/Daily_Planner/yourname.html</div></div></div>
      <div class="step"><div class="step-num">3</div><div class="step-body"><strong>That's it</strong><span>Data updates hourly. Nothing to install, no sheet access needed.</span></div></div>
    </div>
  </div>

  <hr class="divider">

  <div class="section">
    <div class="section-label">Software Team &mdash; What You'll See</div>
    <div class="features">
      <div class="feature"><div class="badge">Priorities</div><div class="feature-title">Urgent jobs first</div><div class="feature-desc">Any job overdue or due within the next 2 weeks, sorted by severity.</div></div>
      <div class="feature"><div class="badge">Active Jobs</div><div class="feature-title">Your full job list</div><div class="feature-desc">Go-live dates, job size, status, and comments &mdash; all in one place.</div></div>
      <div class="feature"><div class="badge">Unassigned</div><div class="feature-title">Jobs needing an owner</div><div class="feature-desc">CWT and NEOPS jobs not yet allocated &mdash; useful for picking up capacity.</div></div>
      <div class="feature"><div class="badge">Completed</div><div class="feature-title">Your history</div><div class="feature-desc">Completed jobs kept for reference, sorted by most recent.</div></div>
    </div>
  </div>

  <div class="section">
    <div class="section-label">Back Office Team (Joe &amp; Anna) &mdash; What You'll See</div>
    <div class="features">
      <div class="feature"><div class="badge green">Task Grid</div><div class="feature-title">Per-job task breakdown</div><div class="feature-desc">City ID, Sim, API, Alerts, Banking Port &mdash; expand any row to see task-level status.</div></div>
      <div class="feature"><div class="badge green">SW Go Live</div><div class="feature-title">Software team's date</div><div class="feature-desc">Each job shows the software team's go-live date alongside your own deadline.</div></div>
      <div class="feature"><div class="badge green">Team View</div><div class="feature-title">My Jobs / Team Jobs toggle</div><div class="feature-desc">Switch between your own jobs and the full Joe + Anna combined list.</div></div>
      <div class="feature"><div class="badge green">Priorities</div><div class="feature-title">Overdue &amp; urgent first</div><div class="feature-desc">Any job with an Issue or due within 2 weeks surfaces at the top automatically.</div></div>
    </div>
  </div>

  <hr class="divider">

  <div class="section">
    <div class="section-label">Your Personal Links</div>
    <div class="member-list">
      <div class="member-row"><div class="member-avatar">E</div><div style="flex:1"><div class="member-name">Emie</div><div class="member-type">Software</div></div><a class="member-link-sm" href="emie.html">emie.html</a></div>
      <div class="member-row"><div class="member-avatar">J</div><div style="flex:1"><div class="member-name">Jay</div><div class="member-type">Software</div></div><a class="member-link-sm" href="jay.html">jay.html</a></div>
      <div class="member-row"><div class="member-avatar">R</div><div style="flex:1"><div class="member-name">Rob</div><div class="member-type">Software</div></div><a class="member-link-sm" href="rob.html">rob.html</a></div>
      <div class="member-row"><div class="member-avatar">R</div><div style="flex:1"><div class="member-name">Ross</div><div class="member-type">Software</div></div><a class="member-link-sm" href="ross.html">ross.html</a></div>
      <div class="member-row"><div class="member-avatar">S</div><div style="flex:1"><div class="member-name">Sofia</div><div class="member-type">Software</div></div><a class="member-link-sm" href="sofia.html">sofia.html</a></div>
      <div class="member-row"><div class="member-avatar">S</div><div style="flex:1"><div class="member-name">Suna</div><div class="member-type">Software</div></div><a class="member-link-sm" href="suna.html">suna.html</a></div>
      <div class="member-row"><div class="member-avatar">T</div><div style="flex:1"><div class="member-name">Tristan</div><div class="member-type">Software</div></div><a class="member-link-sm" href="tristan.html">tristan.html</a></div>
      <div class="member-row"><div class="member-avatar bo">J</div><div style="flex:1"><div class="member-name">Joe</div><div class="member-type">Back Office</div></div><a class="member-link-sm" href="joe.html">joe.html</a></div>
      <div class="member-row"><div class="member-avatar bo">A</div><div style="flex:1"><div class="member-name">Anna</div><div class="member-type">Back Office</div></div><a class="member-link-sm" href="anna.html">anna.html</a></div>
    </div>
  </div>

  <hr class="divider">
  <div class="security"><span style="font-size:18px;flex-shrink:0">&#128274;</span><div class="security-text"><strong>Your data is encrypted.</strong> Each page uses AES-256 encryption &mdash; your personal password is the only way to decrypt your jobs. Even the raw data files are unreadable without it. Your browser remembers the password after the first sign-in.</div></div>
</div>

<!-- Changelog tab -->
<div id="tab-changelog">
%%CHANGELOG_HTML%%
</div>

<script>
(function(){var t=localStorage.getItem('planner_theme')||'dark';document.documentElement.setAttribute('data-theme',t);var b=document.getElementById('theme-btn');if(b)b.innerHTML=t==='dark'?'&#9728; Light':'&#9790; Dark';})();
function toggleTheme(){var t=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';document.documentElement.setAttribute('data-theme',t);localStorage.setItem('planner_theme',t);var b=document.getElementById('theme-btn');if(b)b.innerHTML=t==='dark'?'&#9728; Light':'&#9790; Dark';}
function showTab(name){
  document.getElementById('tab-team').style.display=name==='team'?'flex':'none';
  document.getElementById('tab-about').style.display=name==='about'?'block':'none';
  document.getElementById('tab-changelog').style.display=name==='changelog'?'block':'none';
  document.getElementById('btn-team').classList.toggle('active',name==='team');
  document.getElementById('btn-about').classList.toggle('active',name==='about');
  document.getElementById('btn-changelog').classList.toggle('active',name==='changelog');
  localStorage.setItem('planner_tab',name);
}
(function(){var t=localStorage.getItem('planner_tab')||'team';showTab(t);})();
</script>
</body>
</html>"""


# ── Joe/Anna back-office page template ───────────────────────────────────────

JOE_ANNA_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%%MEMBER%% &mdash; Back Office Planner</title>
<style>
:root{
  --bg:#0e0e20;--bg2:#13132e;--card:#1a1a3a;--border:#26265a;
  --text:#d8d8f0;--muted:#8888c0;--pink:#e91e8c;
  --green:#22c55e;--amber:#f59e0b;--red:#ef4444;--r:8px;
  --bst-bg:rgba(255,255,255,.07);--row-hover:rgba(255,255,255,.03);
}
[data-theme="light"]{
  --bg:#f0f0f8;--bg2:#ffffff;--card:#ffffff;--border:#d0d0e8;
  --text:#1a1a3a;--muted:#5050a0;
  --bst-bg:rgba(0,0,0,.06);--row-hover:rgba(0,0,0,.03);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:var(--bg);color:var(--text);font-size:14px;line-height:1.5;min-height:100vh}
#auth-overlay{position:fixed;inset:0;background:rgba(10,10,28,.97);
  display:flex;align-items:center;justify-content:center;z-index:9999}
[data-theme="light"] #auth-overlay{background:rgba(220,220,240,.97)}
#auth-box{background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:36px 32px;width:340px;text-align:center;display:flex;
  flex-direction:column;align-items:center;gap:14px}
#auth-avatar{width:56px;height:56px;border-radius:50%;background:var(--pink);
  display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:#fff}
#auth-name{font-size:1.1rem;font-weight:700}
#auth-sub{color:var(--muted);font-size:.82rem}
#auth-pw-input{width:100%;padding:10px 12px;border-radius:7px;font-size:.9rem;
  border:1px solid var(--border);background:var(--bg);color:var(--text);outline:none;transition:border .15s}
#auth-pw-input:focus{border-color:var(--pink)}
#auth-pw-submit{width:100%;background:var(--pink);color:#fff;border:none;
  padding:11px;border-radius:7px;font-size:.9rem;font-weight:700;cursor:pointer;transition:opacity .15s}
#auth-pw-submit:hover{opacity:.85}
#auth-pw-err{color:var(--red);font-size:.8rem;text-align:center}
#load-overlay{position:fixed;inset:0;background:rgba(10,10,28,.92);
  display:none;align-items:center;justify-content:center;z-index:9998;
  flex-direction:column;gap:16px}
.load-spin{width:40px;height:40px;border:3px solid rgba(255,255,255,.1);
  border-top-color:var(--pink);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
#load-msg{color:var(--muted);font-size:.85rem}
.hdr{background:var(--bg2);border-bottom:2px solid var(--pink);padding:16px 20px}
.hdr-inner{max-width:1200px;margin:0 auto;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.avatar-wrap{position:relative;flex-shrink:0;cursor:pointer}
.avatar-wrap:hover .avatar{opacity:.85}
.avatar{width:46px;height:46px;border-radius:50%;background:var(--pink);display:flex;
        align-items:center;justify-content:center;font-size:18px;font-weight:700;color:#fff;pointer-events:none;transition:opacity .15s}
#avatar-color-picker{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer;border:none;padding:0;border-radius:50%}
.hdr-name{font-size:1.35rem;font-weight:700}
.hdr-sub{color:var(--muted);font-size:0.78rem}
.hdr-ts{margin-left:auto;text-align:right;font-size:0.75rem;color:var(--muted);line-height:1.7}
.hdr-ts .cur-time{color:var(--text);font-size:1.1rem;font-weight:700;display:block}
.theme-btn{background:none;border:1px solid var(--border);color:var(--muted);
           padding:6px 12px;border-radius:6px;font-size:.76rem;cursor:pointer;white-space:nowrap;flex-shrink:0}
.theme-btn:hover{border-color:var(--pink);color:var(--pink)}
.back-btn{display:none;align-items:center;gap:6px;background:none;
          border:1px solid var(--border);color:var(--muted);
          padding:6px 12px;border-radius:6px;font-size:.76rem;cursor:pointer;
          white-space:nowrap;flex-shrink:0;transition:all .15s;text-decoration:none}
.back-btn:hover{border-color:var(--pink);color:var(--pink)}
.back-btn.visible{display:flex}
.nav{background:var(--bg2);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}
.nav-inner{max-width:1200px;margin:0 auto;display:flex;justify-content:space-between;align-items:center}
.nav-links{display:flex}
.nav a{padding:10px 22px;text-decoration:none;color:var(--muted);font-size:0.78rem;
       font-weight:700;text-transform:uppercase;letter-spacing:.06em;
       border-bottom:3px solid transparent;transition:all .15s}
.nav a:hover,.nav a.act{color:var(--pink);border-color:var(--pink)}
.nav-user{font-size:.72rem;color:var(--muted);display:flex;align-items:center;gap:8px}
.nav-signout{background:none;border:1px solid var(--border);color:var(--muted);
             padding:4px 10px;border-radius:5px;font-size:.7rem;cursor:pointer}
.nav-signout:hover{border-color:var(--red);color:var(--red)}
.team-toggle{display:flex;gap:3px}
.tgl-btn{background:none;border:1px solid var(--border);color:var(--muted);
         padding:4px 12px;border-radius:6px;font-size:.72rem;font-weight:700;cursor:pointer;transition:all .15s}
.tgl-btn.active{background:var(--pink);border-color:var(--pink);color:#fff}
.tgl-btn:hover:not(.active){border-color:var(--pink);color:var(--pink)}
.owner-badge{display:inline-block;font-size:.65rem;font-weight:700;padding:1px 6px;
             border-radius:4px;background:rgba(233,30,140,.15);color:var(--pink);margin-left:4px}
main{max-width:1200px;margin:0 auto;padding:28px 16px}
section{margin-bottom:52px}
.sec-hdr{margin-bottom:6px;display:flex;align-items:baseline;gap:10px}
.sec-hdr h2{font-size:1.05rem;font-weight:700}
.sec-cnt{background:var(--pink);color:#fff;font-size:.7rem;
         padding:2px 9px;border-radius:12px;font-weight:700}
.sec-sub{color:var(--muted);font-size:.78rem;margin-bottom:18px}
.pg{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:14px}
.p-empty{background:var(--card);border:1px solid var(--border);border-radius:var(--r);
         padding:24px;text-align:center;color:var(--green);font-size:.9rem}
.pc{background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:var(--r);
    border-left:4px solid var(--border);padding:14px;display:flex;flex-direction:column;gap:8px}
.pc.issue{border-left-color:var(--red);background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.25)}
.pc.todo{border-left-color:var(--amber);background:rgba(245,158,11,.08);border-color:rgba(245,158,11,.25)}
.pc-ref{font-weight:700;font-size:.88rem}
.pc-cust{font-size:.82rem;color:var(--muted)}
.pc-dates{display:flex;flex-direction:column;gap:3px}
.pc-date{font-size:.75rem;display:flex;gap:6px;align-items:center}
.pc-dl{color:var(--muted);min-width:76px;font-weight:600}
.pc-tasks{display:flex;gap:6px;flex-wrap:wrap;margin-top:2px}
.pc-bottom{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.b{display:inline-block;font-size:.68rem;font-weight:700;padding:2px 8px;border-radius:4px}
.biss{background:rgba(239,68,68,.2);color:var(--red)}
.btodo{background:rgba(245,158,11,.2);color:var(--amber)}
.bdone{background:rgba(34,197,94,.15);color:var(--green)}
.tbl-wrap{overflow-x:auto;border-radius:var(--r);border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{background:var(--bg2);padding:9px 12px;text-align:left;font-size:.7rem;font-weight:700;
   text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--border)}
td{padding:9px 12px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:top}
[data-theme="light"] td{border-bottom:1px solid rgba(0,0,0,.06)}
tr:hover td{background:var(--row-hover)}
td.rc{font-weight:700;font-size:.8rem;white-space:nowrap}
td.dc{white-space:nowrap}
.mut{color:var(--muted)}
.okt{color:var(--green)}
.ambt{color:var(--amber)}
.ovdt{color:var(--red);font-weight:700}
.sw-date{font-size:.72rem;color:var(--muted);white-space:nowrap}
.sw-date.match{color:var(--green)}
.sw-date.mismatch{color:var(--amber)}
.task-grid{display:flex;flex-wrap:wrap;gap:4px;padding:8px 12px 10px}
.tk{font-size:.68rem;padding:2px 8px;border-radius:4px;font-weight:600;white-space:nowrap}
.tk-done{background:rgba(34,197,94,.12);color:var(--green)}
.tk-todo{background:rgba(245,158,11,.15);color:var(--amber)}
.tk-issue{background:rgba(239,68,68,.15);color:var(--red)}
.tk-nr{background:rgba(255,255,255,.06);color:var(--muted)}
.exp-btn{background:none;border:1px solid var(--border);color:var(--muted);
         cursor:pointer;font-size:.68rem;padding:2px 8px;border-radius:4px;transition:all .15s}
.exp-btn:hover,.exp-btn.open{border-color:var(--pink);color:var(--pink)}
.detail-row td{background:var(--card)!important;padding:0}
.toggle-btn{margin-left:8px;background:none;border:1px solid var(--border);color:var(--muted);
            padding:3px 10px;border-radius:6px;font-size:.72rem;cursor:pointer}
.toggle-btn:hover{border-color:var(--pink);color:var(--pink)}
.empty{text-align:center;padding:36px;color:var(--muted);font-size:.88rem}
footer{text-align:center;padding:24px 16px;color:var(--muted);font-size:.72rem;
       border-top:1px solid var(--border);margin-top:20px}
@media(max-width:600px){.pg{grid-template-columns:1fr}th,td{padding:7px 8px}}
</style>
</head>
<body>

<div id="auth-overlay">
  <div id="auth-box">
    <div id="auth-avatar">%%INITIAL%%</div>
    <div id="auth-name">%%MEMBER%%</div>
    <div id="auth-sub">Enter your password to view your planner</div>
    <input type="password" id="auth-pw-input" placeholder="Your password" autocomplete="current-password">
    <button id="auth-pw-submit">Sign In</button>
    <div id="auth-pw-err" style="display:none"></div>
  </div>
</div>
<div id="load-overlay">
  <div class="load-spin"></div>
  <div id="load-msg">Loading your jobs&hellip;</div>
</div>

<header class="hdr">
  <div class="hdr-inner">
    <a id="back-btn" class="back-btn visible" href="index.html">&#8592; All Members</a>
    <div class="avatar-wrap" title="Click to change your accent colour">
      <div class="avatar" id="member-avatar">%%INITIAL%%</div>
      <input type="color" id="avatar-color-picker">
    </div>
    <div>
      <div class="hdr-name">%%MEMBER%%</div>
      <div class="hdr-sub">Back Office &mdash; Software Customisations</div>
    </div>
    <button class="theme-btn" id="theme-btn" onclick="toggleTheme()">&#9728; Light</button>
    <div class="hdr-ts">
      <span class="cur-time" id="current-time">--:--</span>
      <span id="data-fetched-ts"></span>
    </div>
  </div>
</header>

<nav class="nav">
  <div class="nav-inner">
    <div class="nav-links">
      <a href="#priorities" class="act">Priorities</a>
      <a href="#jobs">All Jobs</a>
      <a href="#completed">Completed</a>
    </div>
    <div class="nav-right">
      <div class="team-toggle">
        <button id="toggle-mine"  class="tgl-btn active" onclick="setView(false)">My Jobs</button>
        <button id="toggle-team" class="tgl-btn"        onclick="setView(true)">Team Jobs</button>
      </div>
      <div class="nav-user">
        <span id="nav-user-email"></span>
        <button class="nav-signout" id="nav-signout-btn" style="display:none">Sign out</button>
      </div>
    </div>
  </div>
</nav>

<main>
  <section id="priorities">
    <div class="sec-hdr"><h2>Your Priorities</h2><span class="sec-cnt" id="p-cnt">0</span></div>
    <div class="sec-sub">Jobs with outstanding issues or tasks due soon</div>
    <div id="priorities-content"></div>
  </section>

  <section id="jobs">
    <div class="sec-hdr"><h2>All Active Jobs</h2><span class="sec-cnt" id="j-cnt">0</span></div>
    <div class="sec-sub">Your full pipeline &mdash; SW Go Live shows the software team&rsquo;s planned date</div>
    <div id="jobs-table"></div>
  </section>

  <section id="completed">
    <div class="sec-hdr">
      <h2>Completed Jobs</h2><span class="sec-cnt" id="c-cnt">0</span>
      <button class="toggle-btn" id="comp-toggle" onclick="toggleCompleted()">Show &#9660;</button>
    </div>
    <div class="sec-sub">All tasks done or not required</div>
    <div id="comp-table" style="display:none"></div>
  </section>
</main>

<footer>%%MEMBER%% &mdash; Back Office Planner &middot; Data from Google Sheets &middot; Refreshes hourly</footer>

<script>
(function(){
  var t=localStorage.getItem('planner_theme')||'dark';
  document.documentElement.setAttribute('data-theme',t);
  var b=document.getElementById('theme-btn');
  if(b)b.innerHTML=t==='dark'?'&#9728; Light':'&#9790; Dark';
})();
function toggleTheme(){
  var t=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';
  document.documentElement.setAttribute('data-theme',t);
  localStorage.setItem('planner_theme',t);
  var b=document.getElementById('theme-btn');
  if(b)b.innerHTML=t==='dark'?'&#9728; Light':'&#9790; Dark';
}
function _tick(){
  var el=document.getElementById('current-time');
  if(!el)return;
  var d=new Date();
  el.textContent=String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0');
}
_tick(); setInterval(_tick,30000);

// ── Accent colour ─────────────────────────────────────────────────────────────
(function(){
  var KEY='planner_avc_%%MEMBER%%';
  var c=localStorage.getItem(KEY)||'#e91e8c';
  function _apply(col){
    document.querySelectorAll('.avatar,#auth-avatar').forEach(function(a){a.style.background=col;});
    document.documentElement.style.setProperty('--pink',col);
  }
  _apply(c);
  var pk=document.getElementById('avatar-color-picker');
  if(pk){pk.value=c;pk.addEventListener('input',function(){_apply(pk.value);localStorage.setItem(KEY,pk.value);});}
})();

var JOBS = [], COMPLETED = [], ALL_JOBS = [], ALL_COMPLETED = [];
var _teamView = false;
var CHANGELOG = %%CHANGELOG_JSON%%;

function setView(team){
  _teamView = team;
  document.getElementById('toggle-mine').classList.toggle('active', !team);
  document.getElementById('toggle-team').classList.toggle('active',  team);
  renderPriorities();
  renderJobs();
  renderCompleted();
}
function _activeJobs()      { return _teamView ? ALL_JOBS      : JOBS; }
function _activeCompleted() { return _teamView ? ALL_COMPLETED : COMPLETED; }

var _authOverlay = document.getElementById('auth-overlay');
var _loadOverlay = document.getElementById('load-overlay');
var _navSignout  = document.getElementById('nav-signout-btn');
var MEMBER_PW_HASH = '%%MEMBER_PW_HASH%%';
var _blobKey = 'm';

async function _sha256(s){
  var b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));
  return Array.from(new Uint8Array(b)).map(function(x){return x.toString(16).padStart(2,'0')}).join('');
}
function _b64ToArr(b64){
  var raw=atob(b64),arr=new Uint8Array(raw.length);
  for(var i=0;i<raw.length;i++)arr[i]=raw.charCodeAt(i);
  return arr;
}
async function _decryptBlob(blob,pw){
  try{
    var km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),{name:'PBKDF2'},false,['deriveKey']);
    var key=await crypto.subtle.deriveKey(
      {name:'PBKDF2',salt:_b64ToArr(blob.s),iterations:100000,hash:'SHA-256'},
      km,{name:'AES-GCM',length:256},false,['decrypt']);
    var pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:_b64ToArr(blob.i)},key,_b64ToArr(blob.c));
    return JSON.parse(new TextDecoder().decode(pt));
  }catch(e){return null;}
}
function _clearAuth(){localStorage.removeItem('fp_auth');localStorage.removeItem('fp_pw');localStorage.removeItem('fp_blob');}
var _MAX_ATTEMPTS=5,_LOCKOUT_MS=120000;
function _isLocked(){var t=sessionStorage.getItem('fp_locked');if(!t)return false;if(Date.now()-parseInt(t)<_LOCKOUT_MS)return true;sessionStorage.removeItem('fp_locked');sessionStorage.removeItem('fp_fails');return false;}
function _lockoutSecs(){return Math.ceil((_LOCKOUT_MS-(Date.now()-parseInt(sessionStorage.getItem('fp_locked')||'0')))/1000);}
function _recordFail(){var n=parseInt(sessionStorage.getItem('fp_fails')||'0')+1;sessionStorage.setItem('fp_fails',String(n));if(n>=_MAX_ATTEMPTS)sessionStorage.setItem('fp_locked',String(Date.now()));return n;}
function _showErr(msg){var e=document.getElementById('auth-pw-err');e.textContent=msg;e.style.display='block';}
function _startLockout(){
  var inp=document.getElementById('auth-pw-input');
  var btn=document.getElementById('auth-pw-submit');
  inp.disabled=true;btn.disabled=true;btn.style.opacity='.5';
  (function tick(){
    if(!_isLocked()){inp.disabled=false;btn.disabled=false;btn.style.opacity='';document.getElementById('auth-pw-err').style.display='none';sessionStorage.removeItem('fp_fails');return;}
    _showErr('Too many attempts — try again in '+_lockoutSecs()+'s');
    setTimeout(tick,1000);
  })();
}
async function _checkAuth(){
  if(_isLocked()){_authOverlay.style.display='flex';_startLockout();return;}
  var stored_hash=localStorage.getItem('fp_auth');
  var stored_pw=localStorage.getItem('fp_pw');
  if(stored_hash&&stored_pw){
    _blobKey=(stored_hash===MEMBER_PW_HASH)?'m':(localStorage.getItem('fp_blob')||'m');
    _authOverlay.style.display='none';
    _navSignout.style.display='inline-block';
    _loadData(stored_pw);
    return;
  }
  _authOverlay.style.display='flex';
}
document.getElementById('auth-pw-input').addEventListener('keydown',function(e){
  if(e.key==='Enter')document.getElementById('auth-pw-submit').click();
});
document.getElementById('auth-pw-submit').addEventListener('click',async function(){
  if(_isLocked()){_startLockout();return;}
  var pw=document.getElementById('auth-pw-input').value;
  var h=await _sha256(pw);
  if(h===MEMBER_PW_HASH){
    sessionStorage.removeItem('fp_fails');sessionStorage.removeItem('fp_locked');
    _blobKey='m';
    localStorage.setItem('fp_auth',h);localStorage.setItem('fp_pw',pw);localStorage.setItem('fp_blob','m');
    _authOverlay.style.display='none';
    _navSignout.style.display='inline-block';
    _loadData(pw);
    return;
  }
  // Silently try master blob — no hash exposed in source
  _loadOverlay.style.display='flex';
  fetch('data/%%MEMBER_LOWER%%.json')
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})
  .then(async function(enc){
    if(enc&&enc.v===1){
      var data=await _decryptBlob(enc.x,pw);
      if(data){
        sessionStorage.removeItem('fp_fails');sessionStorage.removeItem('fp_locked');
        _blobKey='x';
        localStorage.setItem('fp_auth',h);localStorage.setItem('fp_pw',pw);localStorage.setItem('fp_blob','x');
        _authOverlay.style.display='none';
        _navSignout.style.display='inline-block';
        _loadOverlay.style.display='none';
        _afterLoad(data);
        return;
      }
    }
    _loadOverlay.style.display='none';
    var n=_recordFail();
    if(_isLocked()){_startLockout();}
    else{_showErr('Incorrect password — '+(_MAX_ATTEMPTS-n)+' attempt'+(_MAX_ATTEMPTS-n===1?'':'s')+' remaining');}
    document.getElementById('auth-pw-input').value='';
  })
  .catch(function(){
    _loadOverlay.style.display='none';
    var n=_recordFail();
    if(_isLocked()){_startLockout();}else{_showErr('Incorrect password');}
    document.getElementById('auth-pw-input').value='';
  });
});
_navSignout.addEventListener('click',function(){_clearAuth();location.reload();});
function _afterLoad(data){
  JOBS          = data.jobs          || [];
  COMPLETED     = data.completed     || [];
  ALL_JOBS      = data.all_jobs      || JOBS;
  ALL_COMPLETED = data.all_completed || COMPLETED;
  _loadOverlay.style.display='none';
  var _ts=document.getElementById('data-fetched-ts');
  if(_ts)_ts.textContent='Updated '+(data.generated_at||'--:--');
  renderPriorities();
  renderJobs();
  renderCompleted();
}
function _loadData(pw){
  _loadOverlay.style.display='flex';
  fetch('data/%%MEMBER_LOWER%%.json')
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})
  .then(async function(enc){
    var data=null;
    if(enc&&enc.v===1){
      data=await _decryptBlob(enc[_blobKey],pw);
      if(!data){_clearAuth();_loadOverlay.style.display='none';_authOverlay.style.display='flex';return;}
    }else{data=enc;}
    _afterLoad(data);
  })
  .catch(function(err){
    _loadOverlay.style.display='none';
    document.getElementById('load-msg').textContent='Failed to load data — please refresh.';
    console.error(err);
  });
}
window.addEventListener('load',_checkAuth);

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function daysLabel(j){
  if(j.days_left===null||j.days_left===undefined) return '<span class="mut">No date</span>';
  if(j.overdue) return '<span class="ovdt">'+Math.abs(j.days_left)+'d overdue</span>';
  if(j.days_left===0) return '<span class="ambt">Due today</span>';
  if(j.days_left<=7)  return '<span class="ambt">'+j.days_left+'d left</span>';
  return '<span class="okt">'+j.days_left+'d</span>';
}

function statusBadge(s){
  if(s==='Issue') return '<span class="b biss">&#9888; Issue</span>';
  if(s==='To Do') return '<span class="b btodo">&#9654; To Do</span>';
  return '<span class="b bdone">&#10003; Done</span>';
}

function taskSummary(j){
  var parts=[];
  if(j.issue_count) parts.push('<span class="b biss">'+j.issue_count+' Issue</span>');
  if(j.todo_count)  parts.push('<span class="b btodo">'+j.todo_count+' To Do</span>');
  if(j.done_count)  parts.push('<span class="b bdone">'+j.done_count+' Done</span>');
  return parts.join(' ');
}

function taskGrid(tasks){
  var html='<div class="task-grid">';
  Object.entries(tasks).forEach(function(kv){
    var name=kv[0], val=kv[1];
    var lv=(val||'').toLowerCase().trim();
    var cls,label;
    if(lv==='issue'){cls='tk-issue';label='&#9888; ';}
    else if(lv===''||lv==='not required'||lv==='na'||lv==='n/a'){cls='tk-nr';label='';}
    else if(lv==='done'){cls='tk-done';label='&#10003; ';}
    else{cls='tk-todo';label='&#9654; ';}
    if(cls!=='tk-nr'){
      html+='<span class="tk '+cls+'">'+label+esc(name)+'</span>';
    }
  });
  html+='</div>';
  return html;
}

function swDateCell(j){
  if(!j.sw_go_live_date) return '<span class="mut sw-date">&mdash;</span>';
  var cls='sw-date';
  if(j.due_date&&j.sw_go_live_date){
    cls+=j.due_date===j.sw_go_live_date?' match':' mismatch';
  }
  return '<span class="'+cls+'" title="SW Team Go Live">'+esc(j.sw_go_live_date)+'</span>';
}

function renderPriorities(){
  var pjobs=_activeJobs().filter(function(j){
    return j.overall_status==='Issue'||j.overdue||(j.days_left!==null&&j.days_left<14);
  }).sort(function(a,b){
    var oa=a.overall_status==='Issue'?0:1,ob=b.overall_status==='Issue'?0:1;
    if(oa!==ob) return oa-ob;
    var da=a.days_left!==null?a.days_left:9999,db=b.days_left!==null?b.days_left:9999;
    return da-db;
  });
  document.getElementById('p-cnt').textContent=pjobs.length;
  var el=document.getElementById('priorities-content');
  if(!pjobs.length){
    el.innerHTML='<div class="p-empty">&#10003; Nothing urgent right now!</div>';
    return;
  }
  var html='<div class="pg">';
  pjobs.forEach(function(j){
    var cls=j.overall_status==='Issue'?'issue':'todo';
    var swRow=j.sw_go_live_date?'<div class="pc-date"><span class="pc-dl">SW Go Live</span>'+esc(j.sw_go_live_date)+'</div>':'';
    var ownerBadge=_teamView&&j.owned_by?'<span class="owner-badge">'+esc(j.owned_by.charAt(0).toUpperCase()+j.owned_by.slice(1))+'</span>':'';
    html+='<div class="pc '+cls+'">'+
      '<div class="pc-ref">'+esc(j.reference)+ownerBadge+'</div>'+
      '<div class="pc-cust">'+esc(j.customer)+'</div>'+
      '<div class="pc-dates">'+
        '<div class="pc-date"><span class="pc-dl">Your Due Date</span>'+(j.due_date?esc(j.due_date):'TBC')+'</div>'+
        swRow+
      '</div>'+
      '<div class="pc-tasks">'+taskSummary(j)+'</div>'+
      '<div class="pc-bottom">'+daysLabel(j)+' '+statusBadge(j.overall_status)+'</div>'+
    '</div>';
  });
  html+='</div>';
  el.innerHTML=html;
}

function renderJobs(){
  var activeJobs=_activeJobs();
  document.getElementById('j-cnt').textContent=activeJobs.length;
  var el=document.getElementById('jobs-table');
  if(!activeJobs.length){el.innerHTML='<div class="empty">No active jobs.</div>';return;}
  var sorted=[...activeJobs].sort(function(a,b){
    var oa=a.overall_status==='Issue'?0:1,ob=b.overall_status==='Issue'?0:1;
    if(oa!==ob) return oa-ob;
    var da=a.due_date_iso||'',db=b.due_date_iso||'';
    if(!da&&db) return 1; if(da&&!db) return -1;
    return da<db?-1:da>db?1:0;
  });
  var ownerCol=_teamView?'<th>Owner</th>':'';
  var ownerSpan=_teamView?9:8;
  var html='<div class="tbl-wrap"><table><thead><tr>'+
    '<th>Reference</th><th>Customer</th><th>Your Due Date</th>'+
    '<th>SW Go Live</th><th>Days</th><th>Status</th><th>Tasks</th>'+ownerCol+'<th></th>'+
    '</tr></thead><tbody>';
  sorted.forEach(function(j){
    var hasTasks=j.tasks&&Object.keys(j.tasks).length>0;
    var ownerCell=_teamView?'<td><span class="owner-badge">'+esc((j.owned_by||'?').charAt(0).toUpperCase()+(j.owned_by||'?').slice(1))+'</span></td>':'';
    html+='<tr>'+
      '<td class="rc">'+esc(j.reference)+'</td>'+
      '<td>'+esc(j.customer)+'</td>'+
      '<td class="dc">'+(j.due_date?esc(j.due_date):'<span class="mut">&mdash;</span>')+'</td>'+
      '<td class="dc">'+swDateCell(j)+'</td>'+
      '<td class="dc">'+daysLabel(j)+'</td>'+
      '<td>'+statusBadge(j.overall_status)+'</td>'+
      '<td>'+taskSummary(j)+'</td>'+
      ownerCell+
      '<td>'+(hasTasks?'<button class="exp-btn">&#9660;</button>':'')+'</td>'+
    '</tr>';
    if(hasTasks){
      html+='<tr class="detail-row" style="display:none"><td colspan="'+ownerSpan+'">'+taskGrid(j.tasks)+'</td></tr>';
    }
  });
  html+='</tbody></table></div>';
  el.innerHTML=html;
  el.querySelector('table').addEventListener('click',function(e){
    var btn=e.target.closest('.exp-btn');
    if(!btn)return;
    var mainRow=btn.closest('tr');
    var dRow=mainRow.nextElementSibling;
    if(dRow&&dRow.classList.contains('detail-row')){
      var open=dRow.style.display!=='none';
      dRow.style.display=open?'none':'table-row';
      btn.innerHTML=open?'&#9660;':'&#9650;';
      btn.classList.toggle('open',!open);
    }
  });
}

function toggleCompleted(){
  var el=document.getElementById('comp-table');
  var btn=document.getElementById('comp-toggle');
  var vis=el.style.display!=='none';
  el.style.display=vis?'none':'block';
  btn.innerHTML=vis?'Show &#9660;':'Hide &#9650;';
}

function renderCompleted(){
  var activeComp=_activeCompleted();
  document.getElementById('c-cnt').textContent=activeComp.length;
  var el=document.getElementById('comp-table');
  if(!activeComp.length){el.innerHTML='<div class="empty">No completed jobs yet.</div>';return;}
  var sorted=[...activeComp].sort(function(a,b){
    return (b.due_date_iso||'').localeCompare(a.due_date_iso||'');
  });
  var ownerCol=_teamView?'<th>Owner</th>':'';
  var html='<div class="tbl-wrap"><table><thead><tr>'+
    '<th>Reference</th><th>Customer</th><th>Due Date</th><th>SW Go Live</th>'+ownerCol+
    '</tr></thead><tbody>';
  sorted.forEach(function(j){
    var ownerCell=_teamView?'<td><span class="owner-badge">'+esc((j.owned_by||'?').charAt(0).toUpperCase()+(j.owned_by||'?').slice(1))+'</span></td>':'';
    html+='<tr>'+
      '<td class="rc">'+esc(j.reference)+'</td>'+
      '<td>'+esc(j.customer)+'</td>'+
      '<td class="dc">'+(j.due_date?esc(j.due_date):'<span class="mut">&mdash;</span>')+'</td>'+
      '<td class="dc">'+swDateCell(j)+'</td>'+
      ownerCell+
    '</tr>';
  });
  html+='</tbody></table></div>';
  el.innerHTML=html;
}

const _secs=['priorities','jobs','completed'],_nl={};
_secs.forEach(function(id){_nl[id]=document.querySelector('.nav a[href="#'+id+'"]');});
window.addEventListener('scroll',function(){
  var cur=_secs[0];
  _secs.forEach(function(id){var el=document.getElementById(id);if(el&&el.getBoundingClientRect().top<=80)cur=id;});
  _secs.forEach(function(id){if(_nl[id])_nl[id].classList.toggle('act',id===cur);});
},{passive:true});
</script>
</body>
</html>"""


ANNOUNCE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Team Planner — Your Personal Job Portal</title>
<style>
  :root{--bg:#f7f8fc;--surface:#ffffff;--surface2:#f0f2fa;--border:#e2e5f0;--text:#111827;--muted:#6b7280;--pink:#e91e8c;--pink-soft:rgba(233,30,140,.08);--pink-soft2:rgba(233,30,140,.14);--green:#16a34a;--green-soft:rgba(22,163,74,.1);--mono:'Courier New','Consolas',monospace}
  @media(prefers-color-scheme:dark){:root{--bg:#0d0f1a;--surface:#161927;--surface2:#1e2235;--border:#2a2e45;--text:#e8eaf2;--muted:#8b90aa;--pink-soft:rgba(233,30,140,.12);--pink-soft2:rgba(233,30,140,.2);--green-soft:rgba(22,163,74,.15)}}
  :root[data-theme="light"]{--bg:#f7f8fc;--surface:#ffffff;--surface2:#f0f2fa;--border:#e2e5f0;--text:#111827;--muted:#6b7280;--pink-soft:rgba(233,30,140,.08);--pink-soft2:rgba(233,30,140,.14);--green-soft:rgba(22,163,74,.1)}
  :root[data-theme="dark"]{--bg:#0d0f1a;--surface:#161927;--surface2:#1e2235;--border:#2a2e45;--text:#e8eaf2;--muted:#8b90aa;--pink-soft:rgba(233,30,140,.12);--pink-soft2:rgba(233,30,140,.2);--green-soft:rgba(22,163,74,.15)}
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:15px;line-height:1.65;padding:40px 20px 80px}
  .wrap{max-width:680px;margin:0 auto}
  .hdr{display:flex;align-items:center;gap:14px;margin-bottom:36px}
  .hdr-icon{width:44px;height:44px;background:var(--pink);border-radius:12px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
  .hdr-eyebrow{font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--pink);margin-bottom:2px}
  .hdr-title{font-size:22px;font-weight:700;color:var(--text);line-height:1.2}
  .intro{background:var(--pink-soft2);border:1px solid rgba(233,30,140,.2);border-radius:12px;padding:18px 20px;margin-bottom:32px;font-size:14.5px}
  .intro strong{color:var(--pink)}
  .section{margin-bottom:32px}
  .section-label{font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--pink);margin-bottom:12px}
  .steps{display:flex;flex-direction:column;gap:10px}
  .step{display:flex;gap:14px;align-items:flex-start;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
  .step-num{flex-shrink:0;width:26px;height:26px;background:var(--pink);color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;margin-top:1px}
  .step-body{flex:1}
  .step-body strong{font-size:14px;display:block;margin-bottom:3px}
  .step-body span{font-size:13px;color:var(--muted)}
  .step-body .url{font-family:var(--mono);font-size:12px;background:var(--surface2);border:1px solid var(--border);border-radius:5px;padding:3px 7px;display:inline-block;margin-top:5px;color:var(--pink);word-break:break-all}
  .features{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  @media(max-width:480px){.features{grid-template-columns:1fr}}
  .feature{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
  .feature-title{font-size:13px;font-weight:700;margin-bottom:4px}
  .feature-desc{font-size:12.5px;color:var(--muted);line-height:1.5}
  .badge{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:2px 7px;border-radius:4px;background:var(--pink-soft);color:var(--pink);display:inline-block;margin-bottom:7px}
  .badge.green{background:var(--green-soft);color:var(--green)}
  .member-list{display:flex;flex-direction:column;gap:8px}
  .member-row{display:flex;align-items:center;gap:12px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:11px 14px}
  .member-avatar{width:34px;height:34px;background:var(--pink);color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0}
  .member-avatar.bo{background:#7c3aed}
  .member-name{font-size:14px;font-weight:600}
  .member-type{font-size:10.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:1px}
  .member-link{font-family:var(--mono);font-size:11.5px;color:var(--pink);text-decoration:none;background:var(--pink-soft);padding:4px 9px;border-radius:6px;white-space:nowrap}
  .member-link:hover{background:var(--pink-soft2)}
  .security{background:var(--green-soft);border:1px solid rgba(22,163,74,.2);border-radius:10px;padding:14px 16px;display:flex;gap:12px;align-items:flex-start;font-size:13.5px}
  .security-text{line-height:1.5}
  .security-text strong{color:var(--green)}
  .divider{border:none;border-top:1px solid var(--border);margin:28px 0}
  .footer{font-size:12px;color:var(--muted);text-align:center;margin-top:40px}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div class="hdr-icon">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="M9 22V12h6v10" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <div>
      <div class="hdr-eyebrow">Flowbird / Arrive &mdash; Software Customisations</div>
      <div class="hdr-title">Your Personal Job Portal</div>
    </div>
  </div>
  <div class="intro">
    We've built a <strong>personal dashboard</strong> for each of you &mdash; a page you can access from anywhere (phone, home, wherever) that shows your active jobs, what's urgent, and key dates. All data comes directly from the team Google Sheet and refreshes automatically every hour. <strong>No more needing to ask Ross</strong> what's on your plate!
  </div>
  <div class="section">
    <div class="section-label">Getting Started</div>
    <div class="steps">
      <div class="step"><div class="step-num">1</div><div class="step-body"><strong>Ask Ross for your personal password</strong><span>Each person has their own unique password &mdash; it only works on your page and can't be used to view anyone else's data.</span></div></div>
      <div class="step"><div class="step-num">2</div><div class="step-body"><strong>Bookmark your personal page</strong><span>Each person has their own URL &mdash; find yours in the list below. Enter your personal password when prompted &mdash; your browser remembers it after that.</span><div class="url">https://rosscox-blip.github.io/Daily_Planner/yourname.html</div></div></div>
      <div class="step"><div class="step-num">3</div><div class="step-body"><strong>That's it</strong><span>Data updates hourly. You don't need to install anything or request access to the Google Sheet.</span></div></div>
    </div>
  </div>
  <hr class="divider">
  <div class="section">
    <div class="section-label">Software Team &mdash; What You'll See</div>
    <div class="features">
      <div class="feature"><div class="badge">Priorities</div><div class="feature-title">Urgent jobs first</div><div class="feature-desc">Any job overdue or due within the next 2 weeks, sorted by severity.</div></div>
      <div class="feature"><div class="badge">Active Jobs</div><div class="feature-title">Your full job list</div><div class="feature-desc">Go-live dates, job size, status, and comments &mdash; all in one place.</div></div>
      <div class="feature"><div class="badge">Unassigned</div><div class="feature-title">Jobs needing an owner</div><div class="feature-desc">CWT and NEOPS jobs not yet allocated &mdash; useful for picking up capacity.</div></div>
      <div class="feature"><div class="badge">Completed</div><div class="feature-title">Your history</div><div class="feature-desc">Completed jobs kept for reference, sorted by most recent.</div></div>
    </div>
  </div>
  <div class="section">
    <div class="section-label">Back Office Team (Joe &amp; Anna) &mdash; What You'll See</div>
    <div class="features">
      <div class="feature"><div class="badge green">Task Grid</div><div class="feature-title">Per-job task breakdown</div><div class="feature-desc">City ID, Sim, API, Alerts, Banking Port &mdash; expand any row to see task-level status.</div></div>
      <div class="feature"><div class="badge green">SW Go Live</div><div class="feature-title">Software team's date</div><div class="feature-desc">Each job shows the software team's confirmed go-live date alongside your own deadline.</div></div>
      <div class="feature"><div class="badge green">Team View</div><div class="feature-title">My Jobs / Team Jobs toggle</div><div class="feature-desc">Switch between your own jobs and the full Joe + Anna combined list &mdash; useful for holiday cover.</div></div>
      <div class="feature"><div class="badge green">Priorities</div><div class="feature-title">Overdue &amp; urgent first</div><div class="feature-desc">Any job with an Issue or due within 2 weeks is surfaced at the top automatically.</div></div>
    </div>
  </div>
  <hr class="divider">
  <div class="section">
    <div class="section-label">Your Personal Links</div>
    <div class="member-list">
      <div class="member-row"><div class="member-avatar">E</div><div style="flex:1"><div class="member-name">Emie</div><div class="member-type">Software</div></div><a class="member-link" href="https://rosscox-blip.github.io/Daily_Planner/emie.html" target="_blank">emie.html</a></div>
      <div class="member-row"><div class="member-avatar">J</div><div style="flex:1"><div class="member-name">Jay</div><div class="member-type">Software</div></div><a class="member-link" href="https://rosscox-blip.github.io/Daily_Planner/jay.html" target="_blank">jay.html</a></div>
      <div class="member-row"><div class="member-avatar">R</div><div style="flex:1"><div class="member-name">Rob</div><div class="member-type">Software</div></div><a class="member-link" href="https://rosscox-blip.github.io/Daily_Planner/rob.html" target="_blank">rob.html</a></div>
      <div class="member-row"><div class="member-avatar">R</div><div style="flex:1"><div class="member-name">Ross</div><div class="member-type">Software</div></div><a class="member-link" href="https://rosscox-blip.github.io/Daily_Planner/ross.html" target="_blank">ross.html</a></div>
      <div class="member-row"><div class="member-avatar">S</div><div style="flex:1"><div class="member-name">Sofia</div><div class="member-type">Software</div></div><a class="member-link" href="https://rosscox-blip.github.io/Daily_Planner/sofia.html" target="_blank">sofia.html</a></div>
      <div class="member-row"><div class="member-avatar">S</div><div style="flex:1"><div class="member-name">Suna</div><div class="member-type">Software</div></div><a class="member-link" href="https://rosscox-blip.github.io/Daily_Planner/suna.html" target="_blank">suna.html</a></div>
      <div class="member-row"><div class="member-avatar">T</div><div style="flex:1"><div class="member-name">Tristan</div><div class="member-type">Software</div></div><a class="member-link" href="https://rosscox-blip.github.io/Daily_Planner/tristan.html" target="_blank">tristan.html</a></div>
      <div class="member-row"><div class="member-avatar bo">J</div><div style="flex:1"><div class="member-name">Joe</div><div class="member-type">Back Office</div></div><a class="member-link" href="https://rosscox-blip.github.io/Daily_Planner/joe.html" target="_blank">joe.html</a></div>
      <div class="member-row"><div class="member-avatar bo">A</div><div style="flex:1"><div class="member-name">Anna</div><div class="member-type">Back Office</div></div><a class="member-link" href="https://rosscox-blip.github.io/Daily_Planner/anna.html" target="_blank">anna.html</a></div>
    </div>
  </div>
  <hr class="divider">
  <div class="security"><span style="font-size:18px;flex-shrink:0">&#128274;</span><div class="security-text"><strong>Your data is encrypted end-to-end.</strong> Each page uses AES-256 encryption. Your personal password is the only way to decrypt your data &mdash; even the raw files are unreadable without it. Knowing someone else&rsquo;s URL does nothing without their password.</div></div>
  <div class="footer">Daily Planner &mdash; Software Customisations &mdash; Flowbird / Arrive &mdash; Data refreshes hourly from the team Google Sheet</div>
</div>
</body>
</html>"""


if __name__ == '__main__':
    main()
