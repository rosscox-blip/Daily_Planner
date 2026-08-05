import csv
import io
import re
from datetime import datetime, timedelta

import requests

from agents.base_agent import BaseAgent
import config

SHEET_ID = "1sR5IkLFrgd2LxdXZbHbHjMlnbpDNzkMVVNzoFAe5h4w"
# IMPORTANT: use the /export endpoint, NOT /gviz/tq.
# gviz respects any filter applied to the sheet — filtered-out rows silently
# disappear from the CSV. This ate ~127 Completed Change Requests including
# ~20 of Tristan's. The /export endpoint ignores filters and returns every row.
BASE_URL = f"https://docs.google.com/spreadsheets/d/{SHEET_ID}/export?format=csv"

# People to exclude — they handle their jobs separately. Any allocated_to value
# that lowercases to one of these (or starts with one followed by a space) is dropped.
# "james" alone is treated as James Brown — there's only one James on the team.
EXCLUDED_MEMBERS = {"james brown", "james"}

# References that legitimately appear across multiple tabs — typically ongoing
# multi-customer projects that use a single placeholder reference.
# Suppresses the "appears in different tabs" cross-tab warning for these.
CROSS_TAB_WHITELIST = {"UK2407S110L"}

# New workflow tabs (May 2026 — replaced Software/Downloads/CALE)
TABS = {
    "New Machine Orders": {
        "url": BASE_URL + "&gid=1778960497",
        "cols": {
            "onecrmlink": 0,
            "trackinglink": 1,
            "model": 2,        # terminal type: CWT, NEOPS, etc.
            "customer": 3,
            "location": 4,
            "num_machines": 5,
            "date_logged": 6,          # col G — added June 2026
            "parts_delivery_date": 7,  # col H — Delivery Date (used as Go Live fallback)
            "go_live_date": 8,         # col I — SW Go Live Date
            "allocated_to": 9,
            "status": 10,
            "level": 11,
            "comments": 12,
            "sales_comments": 13,  # col N — Sales Admin Comments
        },
        "min_cols": 10,
        "done_statuses": {"completed"},
        "completed_statuses": {"completed"},
        "order_type": "New Machine Order",
    },
    "Hardware Upgrades": {
        "url": BASE_URL + "&gid=1511159441",
        "cols": {
            "onecrmlink": 0,
            "trackinglink": 1,
            "model": 2,        # terminal type
            "customer": 3,
            "location": 4,
            "num_machines": 5,
            "date_logged": 6,         # col G — NEW (added June 2026)
            "parts_delivery_date": 7, # col H — extends SLA deadline if parts not in stock
            "go_live_date": 8,        # col I — Go Live Date
            "allocated_to": 9,
            "status": 10,
            "level": 11,
            "comments": 12,
            "sales_comments": 13,  # col N — Inside Sales Comments
        },
        "min_cols": 10,
        "done_statuses": {"completed"},
        "completed_statuses": {"completed"},
        "order_type": "Hardware Upgrade",
    },
    "Change Requests": {
        "url": BASE_URL + "&gid=322490826",
        "cols": {
            "onecrmlink": 0,
            "trackinglink": 1,
            "model": 2,        # terminal type
            "customer": 3,
            "location": 4,
            "num_customisations": 5,
            "num_machines": 6,
            "date_logged": 7,   # col H — when Sales received the job (SLA anchor)
            "due_date": 8,      # col I — Requested Date: date | "ASAP" | "TBC"
            "go_live_date": 9,  # col J — team-confirmed date, or "??"
            "allocated_to": 10, # col K
            "status": 11,       # col L — State
            # col M is a duplicate "OneCRM" column on the sheet — skip it
            "level": 13,        # col N
            "comments": 14,     # col O — Latest Actions Comments (Summary)
            "sales_comments": 15,  # col P — Inside Sales Comments
        },
        "min_cols": 11,
        "done_statuses": {"completed"},
        "completed_statuses": {"completed"},
        "order_type": "Change Request",
    },
}

# 28-day maximum turnaround SLA from Date Logged (Change Requests)
SLA_DAYS = 28

# One-off "reset date" — when Date Logged equals this value, the row was
# bulk-backfilled (not genuinely logged on this date), so SLA/overdue/no-GL
# warnings are suppressed until Sales enters a real value. Set to "" to disable.
BLANKET_DATE_LOGGED = "26/05/2026"

# Tabs that participate in 28-day SLA tracking from Date Logged.
SLA_TRACKED_TABS = {"Change Requests", "Hardware Upgrades"}

# Hardware Upgrades — Parts Delivery cell values that mean "parts are in stock"
# (i.e. no extension to the 28-day SLA). Anything else that parses as a date is
# treated as a future delivery date that can push the SLA deadline outwards.
_PARTS_IN_STOCK_VALUES = {"stock", "in stock", "stocked", "na", "n/a", "-", ""}

# Placeholder values that are not real dates — suppress parse warnings for these
_NON_DATE_PLACEHOLDERS = {"??", "???", "????", "n/a", "na", "tbc", "tbd", "-", "none", "?", "unknown",
                           "asap", "a.s.a.p", "a.s.a.p."}

# Matches references with accidental spaces e.g. "SF- 098679" or "UK- 2512M1048"
_REF_SPACE_RE = re.compile(r'^([A-Za-z]+)-\s+(.+)$')


def _parse_date(date_str):
    """Try to parse a date string in dd/mm/yyyy or d/m/yyyy format."""
    date_str = date_str.strip()
    if not date_str:
        return None
    for fmt in ("%d/%m/%Y", "%d/%m/%y"):
        try:
            dt = datetime.strptime(date_str, fmt)
            # Reject obviously wrong years from typos (e.g. 0204, 0205)
            if dt.year < 2020 or dt.year > 2030:
                continue
            return dt
        except ValueError:
            continue
    return None


def _days_until(due_date):
    """Return number of days from today until due_date, or None."""
    if not due_date:
        return None
    delta = due_date - datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    return delta.days


def _cell(row, idx):
    """Safely get a cell value, stripped."""
    if idx is not None and idx < len(row):
        return row[idx].strip()
    return ""


# All statuses we expect to see on active (non-done) rows
KNOWN_ACTIVE_STATUSES = {
    "to do", "in progress", "blocked/on hold", "queued", "awaiting customer",
}

# Statuses that mean the job is dead — skip the row entirely (no warnings, no display)
EXCLUDED_STATUSES = {"cancelled", "canceled"}

# Requested Date placeholders with special meaning
_ASAP_VALUES = {"asap", "a.s.a.p", "a.s.a.p."}
_TBC_VALUES = {"tbc", "tbd", "?", "??", "???", "????", "unknown"}


def _warning(level, tab, reference, message, refs=None):
    w = {"level": level, "tab": tab, "reference": reference, "message": message}
    if refs:
        w["refs"] = refs
    return w


# How often to actually re-fetch from Google Sheets (seconds)
SHEET_CACHE_TTL = 60  # 1 minute


class CustomisationsAgent(BaseAgent):

    def __init__(self):
        super().__init__("Customisations Agent")
        self._prev_tab_counts = {}
        self._raw_cache = {}        # tab_name -> csv_text
        self._cache_time = None     # when we last fetched from Google

    def _fetch(self):
        if getattr(config, "USE_MOCK_CUSTOMISATIONS", config.USE_MOCK_DATA):
            return self._mock_data()
        return self._fetch_all_tabs()

    def _fetch_all_tabs(self):
        all_jobs = []
        all_completed = []
        all_members = set()
        all_types = set()
        all_sources = set()
        all_warnings = []

        # Only fetch from Google Sheets if cache is stale
        now = datetime.now()
        cache_expired = (
            self._cache_time is None
            or (now - self._cache_time).total_seconds() > SHEET_CACHE_TTL
        )

        for tab_name, tab_config in TABS.items():
            try:
                if cache_expired:
                    # /export returns a 307 redirect that requests follows by default
                    resp = requests.get(tab_config["url"], timeout=30, allow_redirects=True)
                    resp.raise_for_status()
                    resp.encoding = 'utf-8'
                    self._raw_cache[tab_name] = resp.text

                csv_text = self._raw_cache.get(tab_name)
                if not csv_text:
                    continue

                jobs, completed, tab_warnings = self._parse_tab(csv_text, tab_name, tab_config)
                all_jobs.extend(jobs)
                all_completed.extend(completed)
                all_warnings.extend(tab_warnings)
                all_sources.add(tab_name)

                # Row count drop detection
                prev = self._prev_tab_counts.get(tab_name, 0)
                if prev >= 5 and len(jobs) < prev * 0.5:
                    all_warnings.append(_warning(
                        "warning", tab_name, "",
                        f"Active job count dropped from {prev} to {len(jobs)} - check sheet structure",
                    ))
                self._prev_tab_counts[tab_name] = len(jobs)

            except Exception as e:
                all_warnings.append(_warning(
                    "error", tab_name, "",
                    f"Failed to fetch sheet tab: {e}",
                ))

        if cache_expired and self._raw_cache:
            self._cache_time = now

        for j in all_jobs:
            if j["allocated_to"]:
                all_members.add(j["allocated_to"])
            if j["order_type"]:
                all_types.add(j["order_type"])

        # ── Cross-tab data quality checks ────────────────────────────────────

        # 1. Duplicate reference detection
        #
        # BUSINESS RULE: A single SF/UK reference can legitimately appear multiple
        # times within the SAME tab when one job spans multiple work streams, e.g.:
        #   - CWT software change + NEOPS remote download under the same SF number
        #   - Software change + Remote download under the same SF number
        #   - "Smartfolio EPD" appearing N times (customers get one free EPD per year)
        #
        # Therefore: same-tab duplicates are flagged as INFO only.
        # Cross-tab duplicates (same ref in DIFFERENT tabs) are flagged as ERROR
        # because that almost always means a job was entered in the wrong tab.
        ref_to_jobs = {}
        active_refs = {j["reference"] for j in all_jobs if j.get("has_ref") and j["reference"]}
        for j in all_jobs + all_completed:
            if j.get("has_ref") and j["reference"]:
                ref_to_jobs.setdefault(j["reference"], []).append(j)
        for ref, dupes in ref_to_jobs.items():
            if len(dupes) < 2:
                continue
            # Skip if all instances are completed — nothing to action.
            if ref not in active_refs:
                continue
            # Skip whitelisted placeholder references (e.g. ongoing batched projects)
            if ref in CROSS_TAB_WHITELIST:
                continue
            tabs_seen = [d["source"] for d in dupes]
            unique_tabs = set(tabs_seen)
            if len(unique_tabs) > 1:
                # Cross-tab duplicate with at least one active instance — likely a data entry error
                sources = ", ".join(tabs_seen)
                all_warnings.append(_warning(
                    "error", "Multiple tabs", ref,
                    f"Reference '{ref}' appears in different tabs ({sources}) — "
                    f"check if entered in wrong tab",
                    refs=[ref],
                ))
            # Same-tab duplicates are intentional (multi-stream jobs) — no warning

        # 2. Active jobs with no Level (unsized) — exclude TBC/unofficial jobs
        no_level = [j for j in all_jobs if not (j.get("level") or "").strip() and not j.get("is_tbc")]
        if no_level:
            all_warnings.append(_warning(
                "warning", "All tabs", "",
                f"{len(no_level)} active job(s) have no Level set — hours estimates incomplete",
                refs=[j["reference"] for j in no_level],
            ))

        # 3. Active jobs with no team member assigned
        unassigned = [j for j in all_jobs if not j.get("allocated_to")]
        if unassigned:
            all_warnings.append(_warning(
                "warning", "All tabs", "",
                f"{len(unassigned)} active job(s) have no team member assigned",
                refs=[j["reference"] for j in unassigned],
            ))

        # 4. Jobs severely overdue (>60 days) — likely stale entries
        stale = [j for j in all_jobs if j.get("days_left") is not None and j["days_left"] < -60]
        if stale:
            all_warnings.append(_warning(
                "warning", "All tabs", "",
                f"{len(stale)} job(s) are more than 60 days overdue — check if still active",
                refs=[j["reference"] for j in stale],
            ))

        # Sort: overdue first, then by days_left ascending, nulls last
        all_jobs.sort(key=lambda j: (0, j["days_left"]) if j["days_left"] is not None else (1, 9999))

        overdue_count = sum(1 for j in all_jobs if j["overdue"])
        due_soon_count = sum(1 for j in all_jobs if j["due_soon"] and not j["overdue"])

        return {
            "jobs": all_jobs,
            "completed_jobs": all_completed,
            "warnings": all_warnings,
            "filters": {
                "members": sorted(all_members),
                "order_types": sorted(all_types),
                "sources": sorted(all_sources),
            },
            "summary": {
                "total": len(all_jobs),
                "overdue": overdue_count,
                "due_soon": due_soon_count,
                "unassigned": sum(
                    1 for j in all_jobs if not j["allocated_to"]
                ),
                "sla_breach": sum(1 for j in all_jobs if j.get("sla_breach")),
                "awaiting_customer": sum(
                    1 for j in all_jobs if (j.get("status") or "").lower() == "awaiting customer"
                ),
            },
        }

    def _parse_tab(self, csv_text, tab_name, tab_config):
        reader = csv.reader(io.StringIO(csv_text))
        cols = tab_config["cols"]
        min_cols = tab_config["min_cols"]
        done_statuses = tab_config["done_statuses"]
        completed_statuses = tab_config.get("completed_statuses", set())

        # Skip header row
        try:
            next(reader)
        except StopIteration:
            return [], [], []

        jobs = []
        completed_jobs = []
        warnings = []
        no_date_refs = []
        no_ref_count = 0

        # Row-count reconciliation tracking
        raw_row_count = 0
        counted_blank = 0
        counted_short = 0
        counted_excluded = 0
        counted_completed = 0
        counted_cancelled = 0
        counted_no_ref = 0
        counted_active = 0

        order_type = tab_config.get("order_type", "")
        # Known tracking tool names that appear in the Tracking Link column
        _TOOL_NAMES = {"asana", "trello", "link", "n/a", "na", ""}

        for row in reader:
            raw_row_count += 1

            if len(row) < min_cols:
                counted_short += 1
                continue

            customer = _cell(row, cols["customer"])
            status = _cell(row, cols["status"])
            allocated_to = _cell(row, cols["allocated_to"])

            # Treat placeholder allocated_to values as unassigned
            if allocated_to.lower() in {"not yet allocated", "??", "n/a", "", "unallocated"}:
                allocated_to = ""

            # Use the tracking link cell as the reference if it contains a job
            # reference code (UK*, SF*, etc.) rather than a tool name
            tracking = _cell(row, cols.get("trackinglink"))
            if tracking and tracking.lower() not in _TOOL_NAMES:
                reference = tracking
                has_ref = True
            else:
                reference = customer
                has_ref = False

            # Normalise reference: fix accidental spaces e.g. "SF- 098679" → "SF-098679"
            if has_ref:
                m = _REF_SPACE_RE.match(reference)
                if m:
                    clean_ref = f"{m.group(1)}-{m.group(2).strip()}"
                    warnings.append(_warning(
                        "warning", tab_name, clean_ref,
                        f"Reference '{reference}' had extra spaces — auto-corrected to '{clean_ref}'",
                        refs=[clean_ref],
                    ))
                    reference = clean_ref

            if not customer and not status:
                counted_blank += 1
                continue

            # Skip excluded members
            if allocated_to.lower() in EXCLUDED_MEMBERS:
                counted_excluded += 1
                continue

            # Skip cancelled/dead rows — no warnings, no display
            if status.lower() in EXCLUDED_STATUSES:
                counted_excluded += 1
                continue

            # Completed jobs go to a separate list
            _due_col = cols.get("due_date", cols.get("go_live_date"))
            if status.lower() in completed_statuses:
                counted_completed += 1
                due_date_str = _cell(row, _due_col)
                completed_jobs.append({
                    "reference": reference,
                    "customer": customer,
                    "location": _cell(row, cols["location"]),
                    "num_machines": _cell(row, cols.get("num_machines")),
                    "model": _cell(row, cols["model"]),
                    "due_date": due_date_str,
                    "allocated_to": allocated_to,
                    "status": status,
                    "order_type": order_type,
                    "source": tab_name,
                    "level": _cell(row, cols.get("level")),
                    "has_ref": has_ref,
                })
                continue

            # Skip other done statuses
            if status.lower() in done_statuses:
                counted_cancelled += 1
                continue

            # Row has a status but no customer
            if not customer and status:
                no_ref_count += 1
                counted_no_ref += 1
                continue

            counted_active += 1

            # Warning: unrecognised status
            if status and status.lower() not in KNOWN_ACTIVE_STATUSES:
                warnings.append(_warning(
                    "warning", tab_name, reference,
                    f"Unrecognised status: '{status}'",
                    refs=[reference],
                ))

            requested_date_str = _cell(row, cols.get("due_date", cols.get("go_live_date")))
            requested_lc = requested_date_str.lower()
            # ASAP / TBC semantics only exist for Change Requests. For NMO and HW
            # the "due_date" cell is the Go Live Date — placeholder values like "??"
            # there don't carry the same workflow meaning.
            _is_cr = tab_name == "Change Requests"
            is_asap = _is_cr and requested_lc in _ASAP_VALUES
            # Blank Requested Date on a Change Request is treated the same as "TBC"
            # — neither has been officially logged by Sales yet, so warnings stay
            # suppressed until a real date or "ASAP" is entered.
            is_tbc = _is_cr and (
                requested_lc in _TBC_VALUES or requested_date_str == ""
            )
            requested_date = None if (is_asap or is_tbc) else _parse_date(requested_date_str)

            # Date Logged — SLA anchor (all tabs that carry it)
            date_logged_col = cols.get("date_logged")
            date_logged_str = _cell(row, date_logged_col) if date_logged_col is not None else ""
            date_logged = _parse_date(date_logged_str) if date_logged_str else None
            sla_deadline = date_logged + timedelta(days=SLA_DAYS) if date_logged else None

            # NMO / HW: if Date Logged is absent or a TBC placeholder the job
            # hasn't been officially logged yet — treat as unofficial (suppress
            # no-due-date and no-level warnings the same way CR TBC rows are).
            if not _is_cr and date_logged_col is not None:
                _dl_lc = date_logged_str.lower().strip()
                if not date_logged_str or _dl_lc in _TBC_VALUES or _dl_lc in _NON_DATE_PLACEHOLDERS:
                    is_tbc = True

            # Change Requests have a separate Go Live Date (team-confirmed)
            go_live_col = cols.get("go_live_date")
            go_live_date_str = _cell(row, go_live_col) if go_live_col is not None else ""
            go_live_date = (
                _parse_date(go_live_date_str)
                if go_live_date_str and go_live_date_str.lower() not in _NON_DATE_PLACEHOLDERS
                else None
            )

            # Parse Parts / Delivery Date from col 7 (both NMO and HW use it).
            # Used as a planning-date fallback for NMO/HW when Go Live is empty,
            # and as an SLA-deadline extender for HW.
            parts_delivery_col = cols.get("parts_delivery_date")
            parts_delivery_str = _cell(row, parts_delivery_col) if parts_delivery_col is not None else ""
            _pd_lc = parts_delivery_str.lower().strip()
            # "in stock" if it's an exact known marker OR any variant starting with
            # "stock" (e.g. "Stock - ASAP"). Everything else falls through to date-parse.
            parts_in_stock_val = (
                _pd_lc in _PARTS_IN_STOCK_VALUES
                or _pd_lc.startswith("stock")
            )
            parts_delivery_date_val = None if parts_in_stock_val else _parse_date(parts_delivery_str)

            _is_hw_or_nmo = tab_name in ("New Machine Orders", "Hardware Upgrades")
            due_from_delivery = False

            # Planning date precedence:
            #   1. confirmed Go Live (real date)
            #   2. Change Requests only: customer's Requested Date (real date)
            #   3. NMO / HW only: Delivery Date as a real fallback (parts must land
            #      before go-live, so this is the earliest sensible planning anchor)
            #   4. Change Requests only: SLA deadline (Date Logged + 28 days)
            if go_live_date:
                planning_date = go_live_date
                planning_date_str = go_live_date_str
            elif tab_name == "Change Requests" and requested_date:
                planning_date = requested_date
                planning_date_str = requested_date_str
            elif _is_hw_or_nmo and parts_delivery_date_val:
                planning_date = parts_delivery_date_val
                planning_date_str = parts_delivery_str
                due_from_delivery = True
            elif tab_name == "Change Requests" and sla_deadline:
                planning_date = sla_deadline
                planning_date_str = sla_deadline.strftime("%d/%m/%Y")
            else:
                planning_date = None
                planning_date_str = ""

            # SLA tracking applies to Change Requests and Hardware Upgrades.
            # NMO carries Date Logged purely for visibility (no SLA enforcement).
            is_change_request = tab_name == "Change Requests"
            is_sla_tracked = tab_name in SLA_TRACKED_TABS

            # Is this row on the blanket-backfill Date Logged value?
            # Suppresses overdue / SLA / no-due-date warnings on any SLA-tracked tab.
            is_blanket_logged = bool(
                is_sla_tracked
                and BLANKET_DATE_LOGGED and date_logged_str == BLANKET_DATE_LOGGED
            )

            # Hardware Upgrades — parts-aware SLA deadline.
            # Rule from the team: 28-day SLA from Date Logged when parts are in stock.
            # If parts have a real delivery date later than Day 28, the SLA stretches
            # to the parts delivery date (we can't go live before the hardware lands).
            # (parts_delivery_str / parts_delivery_date_val / parts_in_stock_val are
            #  already parsed above in the planning-date block.)
            parts_in_stock = parts_in_stock_val
            parts_delivery_date = parts_delivery_date_val
            effective_deadline = sla_deadline
            if (
                tab_name == "Hardware Upgrades"
                and parts_delivery_date and sla_deadline
                and parts_delivery_date > sla_deadline
            ):
                effective_deadline = parts_delivery_date

            days_left = _days_until(planning_date)
            # Suppress "overdue" flag entirely for blanket-backfill rows
            if is_blanket_logged and days_left is not None and days_left < 0:
                days_left = None

            # SLA breach: Go Live more than 28 days past Date Logged (or past parts
            # delivery for HW). Carve-outs:
            #  1. Blanket-backfill rows — we don't trust the date, no breach.
            #  2. Customer chose a Requested Date >28d out (CR only) — not our fault.
            customer_chose_far_date = bool(
                is_change_request
                and sla_deadline and requested_date and requested_date > sla_deadline
            )
            sla_breach = bool(
                is_sla_tracked
                and effective_deadline and go_live_date and go_live_date > effective_deadline
                and not is_blanket_logged
                and not customer_chose_far_date
            )
            # Go Live Date set but not a valid date (e.g. "??", "Waiting on...") — limbo
            go_live_unconfirmed = bool(
                go_live_date_str and not go_live_date
            )
            # Unscheduled: Change Request with no committed date at all — the planning
            # date was fabricated from Date Logged + 28d SLA. Shouldn't count toward
            # weekly capacity on the workload heatmap.
            unscheduled = bool(
                date_logged_col is not None
                and not go_live_date
                and not requested_date
            )

            # Warning: date string exists, isn't a placeholder, but couldn't be parsed
            for lbl, ds, dt in [("Requested Date", requested_date_str, requested_date),
                                 ("Go Live Date", go_live_date_str, go_live_date),
                                 ("Date Logged", date_logged_str, date_logged)]:
                if not ds or dt:
                    continue
                ds_lc = ds.lower()
                # ASAP / TBC are valid voice-of-customer for Requested Date only
                if lbl == "Requested Date" and (ds_lc in _ASAP_VALUES or ds_lc in _TBC_VALUES):
                    continue
                if ds_lc in _NON_DATE_PLACEHOLDERS:
                    continue
                warnings.append(_warning(
                    "warning", tab_name, reference,
                    f"Unparseable {lbl}: '{ds}'",
                    refs=[reference],
                ))

            # Warning: SLA breach (Go Live past the effective deadline).
            # CR: deadline = Date Logged + 28d
            # HW: deadline = max(Date Logged + 28d, Parts Delivery Date)
            if sla_breach:
                over = (go_live_date - effective_deadline).days
                anchor = (
                    "parts delivery date" if (effective_deadline != sla_deadline)
                    else "28-day deadline from Date Logged"
                )
                warnings.append(_warning(
                    "warning", tab_name, reference,
                    f"SLA breach: Go Live is {over} day(s) past the {anchor}",
                    refs=[reference],
                ))

            # Warning: SLA-tracked row logged but no Date Logged set.
            # TBC (CR-only) and blanket rows are excluded.
            if is_sla_tracked and date_logged_col is not None and not date_logged_str and not is_tbc:
                warnings.append(_warning(
                    "warning", tab_name, reference,
                    "Missing Date Logged — SLA cannot be calculated",
                    refs=[reference],
                ))

            # Track missing/unknown planning dates (skip TBC and blanket-backfill rows)
            if not is_tbc and not is_blanket_logged and (
                not planning_date_str or planning_date_str.lower() in _NON_DATE_PLACEHOLDERS
            ):
                no_date_refs.append(reference)

            # Days in Queue — how long this job has been sitting since Date Logged.
            # Negative means a future-dated row (typo most likely).
            days_in_queue = (
                (datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
                 - date_logged).days
                if date_logged else None
            )

            # Raw Go Live cell (regardless of tab). For CR that's the dedicated
            # go_live_date column; for NMO/HW it's the due_date column.
            if tab_name == "Change Requests":
                raw_go_live_str = go_live_date_str
            else:
                raw_go_live_str = _cell(row, cols.get("due_date", cols.get("go_live_date")))

            # Sort bucket for the drill panels:
            #   0 = READY: NMO/HW with parts in stock and no confirmed Go Live
            #   1 = SCHEDULED: has a real committed date (Go Live / Requested / Delivery)
            #   2 = FRESH: CR still on the 28-day SLA clock (no real date yet)
            #   3 = NO DATE: nothing to plan on — parked
            has_real_date = bool(go_live_date or requested_date or (
                _is_hw_or_nmo and parts_delivery_date_val
            ))
            if _is_hw_or_nmo and parts_in_stock_val and not go_live_date:
                sort_bucket = 0
            elif has_real_date:
                sort_bucket = 1
            elif tab_name == "Change Requests" and sla_deadline:
                sort_bucket = 2
            else:
                sort_bucket = 3

            jobs.append({
                "reference": reference,
                "servicenow": "",
                "customer": customer,
                "location": _cell(row, cols["location"]),
                "num_customisations": _cell(row, cols.get("num_customisations")),
                "num_machines": _cell(row, cols.get("num_machines")),
                "model": _cell(row, cols["model"]),
                "due_date": planning_date_str,
                "due_date_iso": planning_date.strftime("%Y-%m-%d") if planning_date else "",
                "requested_date": requested_date_str if go_live_col is not None else "",
                "go_live_date": raw_go_live_str,          # raw Go Live cell for every tab
                "date_logged": date_logged_str if date_logged_col is not None else "",
                "sort_bucket": sort_bucket,
                "days_in_queue": days_in_queue,
                "parts_delivery_date": parts_delivery_str if parts_delivery_col is not None else "",
                "parts_in_stock": parts_in_stock if parts_delivery_col is not None else False,
                "due_from_delivery": due_from_delivery,
                "sla_deadline": sla_deadline.strftime("%d/%m/%Y") if sla_deadline else "",
                "effective_deadline": effective_deadline.strftime("%d/%m/%Y") if effective_deadline else "",
                "sla_breach": sla_breach,
                "go_live_unconfirmed": go_live_unconfirmed,
                "unscheduled": unscheduled,
                "blanket_logged": is_blanket_logged,
                "customer_chose_far_date": customer_chose_far_date,
                "is_asap": is_asap,
                "is_tbc": is_tbc,
                "days_left": days_left,
                "due_soon": days_left is not None and days_left <= 5,
                "overdue": days_left is not None and days_left < 0,
                "allocated_to": allocated_to,
                "status": status,
                "order_type": order_type,
                "source": tab_name,
                "comments": _cell(row, cols["comments"]),
                "sales_comments": _cell(row, cols.get("sales_comments")),
                "level": _cell(row, cols.get("level")),
                "onecrmlink": _cell(row, cols.get("onecrmlink")),
                "trackinglink": _cell(row, cols.get("trackinglink")),
                "has_ref": has_ref,
            })

        # Grouped warnings with refs
        if no_date_refs:
            # Change Requests workflow uses Go Live Date — message reflects that
            label = (
                "No Go Live Date set"
                if tab_name == "Change Requests"
                else "with no due date"
            )
            warnings.append(_warning(
                "warning", tab_name, "",
                (f"{len(no_date_refs)} job(s) — {label}"
                 if tab_name == "Change Requests"
                 else f"{len(no_date_refs)} job(s) with no due date"),
                refs=no_date_refs,
            ))
        if no_ref_count > 0:
            warnings.append(_warning(
                "warning", tab_name, "",
                f"{no_ref_count} row(s) with no reference",
            ))

        # Row-count reconciliation: every row must be accounted for
        accounted = (counted_blank + counted_short + counted_excluded +
                     counted_completed + counted_cancelled + counted_no_ref + counted_active)
        if accounted != raw_row_count:
            missing = raw_row_count - accounted
            warnings.append(_warning(
                "error", tab_name, "",
                f"Row reconciliation failed: {missing} row(s) unaccounted for "
                f"(raw={raw_row_count}, accounted={accounted})",
            ))

        return jobs, completed_jobs, warnings

    def _empty_result(self):
        return {
            "jobs": [],
            "completed_jobs": [],
            "warnings": [],
            "filters": {"members": [], "order_types": [], "sources": []},
            "summary": {"total": 0, "overdue": 0, "due_soon": 0, "not_yet_allocated": 0},
        }

    def _mock_data(self):
        now = datetime.now()
        jobs = [
            {
                "reference": "SF-097481",
                "servicenow": "INC0480556",
                "customer": "NSL Services Ltd - Durham",
                "location": "Various",
                "num_customisations": "13",
                "num_machines": "89",
                "model": "Strada & Stelio",
                "due_date": (now + timedelta(days=3)).strftime("%d/%m/%Y"),
                "due_date_iso": (now + timedelta(days=3)).strftime("%Y-%m-%d"),
                "days_left": 3,
                "due_soon": True,
                "overdue": False,
                "allocated_to": "Robert Smith",
                "status": "Not Started",
                "order_type": "Change Request",
                "source": "Software",
                "comments": "NON-Centralised Stelio and Strada Evo",
            },
            {
                "reference": "UK2602S021",
                "servicenow": "INC0481354",
                "customer": "Bridgend County Borough Council",
                "location": "Various",
                "num_customisations": "5",
                "num_machines": "8",
                "model": "Strada Evo",
                "due_date": (now + timedelta(days=2)).strftime("%d/%m/%Y"),
                "due_date_iso": (now + timedelta(days=2)).strftime("%Y-%m-%d"),
                "days_left": 2,
                "due_soon": True,
                "overdue": False,
                "allocated_to": "Robert Smith",
                "status": "On Query",
                "order_type": "New Machines",
                "source": "Software",
                "comments": "Generic Software samples & Spec Queries sent to customer",
            },
            {
                "reference": "SF-096992",
                "servicenow": "INC0481496",
                "customer": "Westmoreland & Furness",
                "location": "Various",
                "num_customisations": "2",
                "num_machines": "13",
                "model": "Strada Evo",
                "due_date": (now + timedelta(days=1)).strftime("%d/%m/%Y"),
                "due_date_iso": (now + timedelta(days=1)).strftime("%Y-%m-%d"),
                "days_left": 1,
                "due_soon": True,
                "overdue": False,
                "allocated_to": "Robert Smith",
                "status": "On Query",
                "order_type": "Change Request",
                "source": "Downloads",
                "comments": "Spec Queries (Bank Hols) - Customer to confirm",
            },
            {
                "reference": "UK2307C091S",
                "servicenow": "",
                "customer": "Cumberland Council",
                "location": "Talkin Tarn",
                "num_customisations": "1",
                "num_machines": "1",
                "model": "S5",
                "due_date": (now + timedelta(days=4)).strftime("%d/%m/%Y"),
                "due_date_iso": (now + timedelta(days=4)).strftime("%Y-%m-%d"),
                "days_left": 4,
                "due_soon": True,
                "overdue": False,
                "allocated_to": "Tristan Pointer",
                "status": "Awaiting Banking",
                "order_type": "New Machines",
                "source": "CALE",
                "comments": "Awaiting Banking details",
            },
            {
                "reference": "SF-097555",
                "servicenow": "INC0479913",
                "customer": "The Crown Estate",
                "location": "Home Park Public and King Edward VII",
                "num_customisations": "1",
                "num_machines": "8",
                "model": "Strada Evo",
                "due_date": (now + timedelta(days=0)).strftime("%d/%m/%Y"),
                "due_date_iso": (now + timedelta(days=0)).strftime("%Y-%m-%d"),
                "days_left": 0,
                "due_soon": True,
                "overdue": False,
                "allocated_to": "Robert Smith",
                "status": "Awaiting Banking",
                "order_type": "Change Request",
                "source": "Software",
                "comments": "Awaiting Parkfolio & Banking Port Activations",
            },
            {
                "reference": "UK2504S087R",
                "servicenow": "",
                "customer": "Kirklees MBC",
                "location": "Halifax Leisure Centre",
                "num_customisations": "1",
                "num_machines": "1",
                "model": "S5",
                "due_date": (now + timedelta(days=12)).strftime("%d/%m/%Y"),
                "due_date_iso": (now + timedelta(days=12)).strftime("%Y-%m-%d"),
                "days_left": 12,
                "due_soon": False,
                "overdue": False,
                "allocated_to": "Jay Basaliyal",
                "status": "In Progress",
                "order_type": "New Machines",
                "source": "CALE",
                "comments": "",
            },
            {
                "reference": "SF-054923",
                "servicenow": "",
                "customer": "Ayrshire Roads Alliance",
                "location": "Various",
                "num_customisations": "4",
                "num_machines": "11",
                "model": "Strada Evo",
                "due_date": (now + timedelta(days=8)).strftime("%d/%m/%Y"),
                "due_date_iso": (now + timedelta(days=8)).strftime("%Y-%m-%d"),
                "days_left": 8,
                "due_soon": False,
                "overdue": False,
                "allocated_to": "",
                "status": "Unassigned",
                "order_type": "Change Request",
                "source": "Software",
                "comments": "",
            },
            {
                "reference": "SF-098294",
                "servicenow": "",
                "customer": "Green Parking",
                "location": "The Archers",
                "num_customisations": "1",
                "num_machines": "1",
                "model": "Strada Evo",
                "due_date": (now + timedelta(days=15)).strftime("%d/%m/%Y"),
                "due_date_iso": (now + timedelta(days=15)).strftime("%Y-%m-%d"),
                "days_left": 15,
                "due_soon": False,
                "overdue": False,
                "allocated_to": "",
                "status": "Spec Check",
                "order_type": "Change Request",
                "source": "Software",
                "comments": "",
            },
        ]

        jobs.sort(key=lambda j: (0, j["days_left"]) if j["days_left"] is not None else (1, 9999))

        all_members = sorted({j["allocated_to"] for j in jobs if j["allocated_to"]})
        all_types = sorted({j["order_type"] for j in jobs})
        all_sources = sorted({j["source"] for j in jobs})

        return {
            "jobs": jobs,
            "completed_jobs": [],
            "warnings": [],
            "filters": {
                "members": all_members,
                "order_types": all_types,
                "sources": all_sources,
            },
            "summary": {
                "total": len(jobs),
                "overdue": sum(1 for j in jobs if j["overdue"]),
                "due_soon": sum(1 for j in jobs if j["due_soon"] and not j["overdue"]),
                "unassigned": sum(1 for j in jobs if j["status"].lower() == "unassigned"),
            },
        }
