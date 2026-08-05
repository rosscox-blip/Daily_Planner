import csv
import io
from datetime import datetime

import requests

from agents.base_agent import BaseAgent
import config

BANKING_SHEET_ID = "1iyK8bUSfoAvv43gJ-o9ATuTCy-4TzHAFmKBYWPyMMkE"
BANKING_URL = (
    f"https://docs.google.com/spreadsheets/d/{BANKING_SHEET_ID}"
    "/gviz/tq?tqx=out:csv"
)

# Cache raw CSV for 5 minutes
SHEET_CACHE_TTL = 300

# Task columns to track (display name -> header search keywords)
TASK_COLUMNS = [
    ("City ID", "city id"),
    ("Sim", "sim"),
    ("API", "api"),
    ("Alerts", "alerts"),
    ("PRM", "prm"),
    ("Banking Port", "banking port"),
    ("Create Acceptor", "create acceptor"),
    ("Archipel", "archipel"),
    ("Acceptor Routing", "acceptor routing"),
    ("Bank Test", "bank test"),
]

# References that indicate standalone jobs (not linked to customisations)
STANDALONE_REFS = {"n/a", "na", "", "mid change"}


def normalise_ref(ref):
    """Normalise a reference for matching across sheets."""
    return ref.strip().upper()


def _find_col(headers, keyword):
    """Find column index by searching for keyword in header text (case-insensitive)."""
    kw = keyword.lower()
    for i, h in enumerate(headers):
        if kw in h.lower():
            return i
    return None


def _cell(row, idx):
    """Safely get a stripped cell value."""
    if idx is not None and idx < len(row):
        return row[idx].strip()
    return ""


def _parse_banking_date(date_str):
    """Parse dates in MM/DD/YYYY format (American, used by banking sheet)."""
    date_str = date_str.strip()
    if not date_str:
        return None
    for fmt in ("%m/%d/%Y", "%m/%d/%y", "%d/%m/%Y", "%d/%m/%y"):
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.year < 2020 or dt.year > 2030:
                continue
            return dt
        except ValueError:
            continue
    return None


def _derive_status(tasks, update_trello):
    """Derive a single banking_status from the task columns and Update Trello."""
    trello = update_trello.lower()

    if trello == "done":
        # Even if complete, flag issues
        if any(v.lower() == "issue" for v in tasks.values()):
            return "issue"
        return "complete"

    if any(v.lower() == "issue" for v in tasks.values()):
        return "issue"

    active_values = {v.lower() for v in tasks.values() if v}
    has_work = "done" in active_values or "to do" in active_values

    if has_work:
        return "in_progress"

    return "not_started"


def _count_progress(tasks):
    """Count done/total tasks (excluding Not Required and empty)."""
    applicable = {k: v for k, v in tasks.items() if v and v.lower() != "not required"}
    done = sum(1 for v in applicable.values() if v.lower() == "done")
    return done, len(applicable)


def _warning(level, reference, message):
    return {"level": level, "tab": "Banking", "reference": reference, "message": message}


def _is_standalone(ref):
    """Check if a reference indicates a standalone back office job."""
    normalised = ref.strip().lower()
    if normalised in STANDALONE_REFS:
        return True
    if "mid change" in normalised:
        return True
    if "mor" in normalised.split():
        return True
    return False


class BankingAgent(BaseAgent):

    def __init__(self):
        super().__init__("Banking Agent")
        self._raw_cache = None
        self._cache_time = None

    def _fetch(self):
        if getattr(config, "USE_MOCK_BANKING", False):
            return self._mock_data()
        return self._fetch_sheet()

    def _fetch_sheet(self):
        now = datetime.now()
        cache_expired = (
            self._cache_time is None
            or (now - self._cache_time).total_seconds() > SHEET_CACHE_TTL
        )

        if cache_expired:
            resp = requests.get(BANKING_URL, timeout=30)
            resp.raise_for_status()
            self._raw_cache = resp.text
            self._cache_time = now

        return self._parse_csv(self._raw_cache)

    def _parse_csv(self, csv_text):
        reader = csv.reader(io.StringIO(csv_text))

        # Parse header row to find columns by name
        try:
            headers = next(reader)
        except StopIteration:
            return self._empty_result()

        col_customer = _find_col(headers, "customer")
        col_ref = _find_col(headers, "job ref")
        col_owned = _find_col(headers, "owned by")
        col_due = _find_col(headers, "due date")
        col_type = _find_col(headers, "type")
        col_trello = _find_col(headers, "update trello")
        col_comments = _find_col(headers, "comments")
        col_sims = _find_col(headers, "no of sims")

        # Find task columns by header keyword
        task_col_map = {}
        for display_name, keyword in TASK_COLUMNS:
            idx = _find_col(headers, keyword)
            if idx is not None:
                task_col_map[display_name] = idx

        warnings = []

        if col_ref is None:
            warnings.append(_warning("error", "", "Could not find 'Job REF' column in header"))
            return {**self._empty_result(), "warnings": warnings}

        if col_trello is None:
            warnings.append(_warning("error", "", "Could not find 'Update Trello' column in header"))

        all_jobs = []
        banking_by_ref = {}
        standalone_jobs = []

        for row in reader:
            if not any(cell.strip() for cell in row):
                continue

            reference = _cell(row, col_ref)
            customer = _cell(row, col_customer)
            owned_by = _cell(row, col_owned)
            due_date_str = _cell(row, col_due)
            job_type = _cell(row, col_type)
            update_trello = _cell(row, col_trello)
            comments = _cell(row, col_comments)
            num_sims = _cell(row, col_sims)

            due_date = _parse_banking_date(due_date_str)

            # Build tasks dict
            tasks = {}
            for display_name, col_idx in task_col_map.items():
                tasks[display_name] = _cell(row, col_idx)

            banking_status = _derive_status(tasks, update_trello)
            done_count, total_count = _count_progress(tasks)

            job = {
                "customer": customer,
                "reference": reference,
                "reference_key": normalise_ref(reference),
                "owned_by": owned_by,
                "due_date": due_date_str,
                "due_date_iso": due_date.strftime("%Y-%m-%d") if due_date else "",
                "type": job_type,
                "tasks": tasks,
                "update_trello": update_trello,
                "banking_status": banking_status,
                "has_issue": any(v.lower() == "issue" for v in tasks.values()),
                "progress": f"{done_count}/{total_count}",
                "done_count": done_count,
                "total_count": total_count,
                "comments": comments,
                "num_sims": num_sims,
                "is_standalone": _is_standalone(reference),
            }

            all_jobs.append(job)

            if job["is_standalone"]:
                standalone_jobs.append(job)
            else:
                ref_key = normalise_ref(reference)
                if ref_key:
                    banking_by_ref[ref_key] = job

        # Summaries
        summary = {
            "total": len(all_jobs),
            "complete": sum(1 for j in all_jobs if j["banking_status"] == "complete"),
            "in_progress": sum(1 for j in all_jobs if j["banking_status"] == "in_progress"),
            "issues": sum(1 for j in all_jobs if j["banking_status"] == "issue"),
            "not_started": sum(1 for j in all_jobs if j["banking_status"] == "not_started"),
            "standalone": len(standalone_jobs),
        }

        owners = sorted({j["owned_by"] for j in all_jobs if j["owned_by"]})

        return {
            "banking_jobs": all_jobs,
            "banking_by_ref": banking_by_ref,
            "standalone_jobs": standalone_jobs,
            "summary": summary,
            "owners": owners,
            "warnings": warnings,
        }

    def _empty_result(self):
        return {
            "banking_jobs": [],
            "banking_by_ref": {},
            "standalone_jobs": [],
            "summary": {"total": 0, "complete": 0, "in_progress": 0, "issues": 0, "not_started": 0, "standalone": 0},
            "owners": [],
            "warnings": [],
        }

    def _mock_data(self):
        return {
            "banking_jobs": [],
            "banking_by_ref": {
                "SF-097555": {
                    "customer": "The Crown Estate",
                    "reference": "SF-097555",
                    "reference_key": "SF-097555",
                    "owned_by": "Joe",
                    "due_date": "04/21/2026",
                    "due_date_iso": "2026-04-21",
                    "type": "PARKEON",
                    "tasks": {"City ID": "Done", "Sim": "To Do", "API": "", "Alerts": "", "PRM": "", "Banking Port": "Issue", "Create Acceptor": "Issue", "Archipel": "Issue", "Acceptor Routing": "Issue", "Bank Test": "Issue"},
                    "update_trello": "Issue",
                    "banking_status": "issue",
                    "has_issue": True,
                    "progress": "1/6",
                    "done_count": 1,
                    "total_count": 6,
                    "comments": "Waiting for MOR",
                    "num_sims": "8",
                    "is_standalone": False,
                },
                "UK2602S021": {
                    "customer": "Bridgend County Borough Council",
                    "reference": "UK2602S021",
                    "reference_key": "UK2602S021",
                    "owned_by": "Joe",
                    "due_date": "04/24/2026",
                    "due_date_iso": "2026-04-24",
                    "type": "PARKEON",
                    "tasks": {"City ID": "", "Sim": "Done", "API": "", "Alerts": "", "PRM": "", "Banking Port": "", "Create Acceptor": "", "Archipel": "Done", "Acceptor Routing": "", "Bank Test": ""},
                    "update_trello": "Done",
                    "banking_status": "complete",
                    "has_issue": False,
                    "progress": "2/2",
                    "done_count": 2,
                    "total_count": 2,
                    "comments": "",
                    "num_sims": "",
                    "is_standalone": False,
                },
            },
            "standalone_jobs": [],
            "summary": {"total": 2, "complete": 1, "in_progress": 0, "issues": 1, "not_started": 0, "standalone": 0},
            "owners": ["Joe"],
            "warnings": [],
        }
