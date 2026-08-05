"""
joe_anna_agent.py
Fetches Joe & Anna's back-office job tracking Google Sheet.
Sheet: https://docs.google.com/spreadsheets/d/1iyK8bUSfoAvv43gJ-o9ATuTCy-4TzHAFmKBYWPyMMkE/
"""
import csv
import io
import time
from datetime import datetime

import requests

SHEET_ID = '1iyK8bUSfoAvv43gJ-o9ATuTCy-4TzHAFmKBYWPyMMkE'
BASE_URL  = (f'https://docs.google.com/spreadsheets/d/{SHEET_ID}'
             f'/export?format=csv&gid=0')
CACHE_TTL = 60  # seconds

TASK_COLS = [
    'City ID', 'Sim', 'API', 'Alerts', 'PRM',
    'Banking Port', 'Create Acceptor', 'Archipel', 'Acceptor Routing',
    'Bank test', 'Update Trello',
]

_DONE_VALS = {'done', 'not required', 'na', 'n/a', ''}


def _overall_status(tasks):
    if tasks.get('Update Trello', '').lower().strip() == 'done':
        return 'Done'
    vals = [v.lower().strip() for v in tasks.values()]
    if any(v == 'issue' for v in vals):
        return 'Issue'
    if any(v not in _DONE_VALS for v in vals):
        return 'To Do'
    return 'Done'


def _task_counts(tasks):
    todo = issue = done = 0
    for v in tasks.values():
        lv = v.lower().strip()
        if lv == 'issue':
            issue += 1
        elif lv in _DONE_VALS:
            done += 1
        else:
            todo += 1
    return todo, issue, done


def _parse_date(s):
    for fmt in ('%d/%m/%Y', '%m/%d/%Y'):
        try:
            d = datetime.strptime(s.strip(), fmt)
            return d.strftime('%Y-%m-%d'), (d - datetime.now()).days
        except ValueError:
            continue
    return '', None


class JoeAnnaAgent:
    def __init__(self):
        self.data   = {}
        self.status = 'idle'
        self.error  = None
        self._cache_time = 0

    def poll(self):
        now = time.time()
        if now - self._cache_time < CACHE_TTL and self.status == 'ok':
            return
        try:
            resp = requests.get(BASE_URL, timeout=15)
            resp.raise_for_status()
            resp.encoding = 'utf-8'
            self._parse(resp.text)
            self.status = 'ok'
            self.error  = None
            self._cache_time = now
        except Exception as e:
            self.status = 'error'
            self.error  = str(e)

    def _parse(self, csv_text):
        rows = list(csv.reader(io.StringIO(csv_text)))

        # Locate header row (starts with 'Customer')
        header_idx = next(
            (i for i, r in enumerate(rows) if r and r[0].strip() == 'Customer'),
            None
        )
        if header_idx is None:
            raise ValueError('Header row not found in Joe/Anna sheet')

        headers   = [h.strip() for h in rows[header_idx]]
        task_idx  = {col: headers.index(col) for col in TASK_COLS if col in headers}
        com_idx   = headers.index('Comments') if 'Comments' in headers else None

        jobs, completed = [], []

        for row in rows[header_idx + 1:]:
            if not row or not any(c.strip() for c in row):
                continue

            def g(i, d=''):
                return row[i].strip() if i is not None and i < len(row) else d

            reference = g(1)
            if not reference:
                continue

            tasks    = {col: g(idx) for col, idx in task_idx.items()}
            status   = _overall_status(tasks)
            todo_n, issue_n, done_n = _task_counts(tasks)
            iso, days = _parse_date(g(3))

            job = {
                'reference':       reference,
                'customer':        g(0),
                'owned_by':        g(2).lower(),
                'due_date':        g(3),
                'due_date_iso':    iso,
                'days_left':       days,
                'overdue':         days is not None and days < 0,
                'job_type':        g(4),
                'overall_status':  status,
                'tasks':           tasks,
                'todo_count':      todo_n,
                'issue_count':     issue_n,
                'done_count':      done_n,
                'comments':        g(com_idx),
                'sw_go_live_date': '',  # cross-referenced by export script
            }

            (completed if status == 'Done' else jobs).append(job)

        self.data = {'jobs': jobs, 'completed_jobs': completed}

    def get_data(self):
        return self.data

    def get_status(self):
        return self.status
