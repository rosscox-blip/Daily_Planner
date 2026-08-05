from datetime import datetime, timedelta
from agents.base_agent import BaseAgent
import config
import json
import os


class ServiceNowAgent(BaseAgent):

    def __init__(self):
        super().__init__("ServiceNow Agent")
        self.team = self._load_team()

    def _load_team(self):
        team_file = os.path.join(os.path.dirname(__file__), "..", "data", "team.json")
        with open(team_file, "r") as f:
            return json.load(f)

    def _fetch(self):
        if config.USE_MOCK_SERVICENOW:
            return self._mock_data()
        return self._fetch_servicenow()

    def _fetch_servicenow(self):
        # Phase 3: Real ServiceNow integration
        return self._mock_data()

    def _mock_data(self):
        now = datetime.now()
        members = self.team["team"]

        tickets = [
            {
                "id": "INC00451289",
                "short_description": "Sunderland barrier fault - entry lane 2",
                "assigned_to": "Emie",
                "workstream": "CWT",
                "priority": "high",
                "state": "In Progress",
                "opened": (now - timedelta(hours=4)).strftime("%d/%m %H:%M"),
                "sla_status": "on_track",
            },
            {
                "id": "INC00451301",
                "short_description": "Guildford P&D terminal 4 offline",
                "assigned_to": "Jay",
                "workstream": "CWT",
                "priority": "critical",
                "state": "New",
                "opened": (now - timedelta(minutes=15)).strftime("%d/%m %H:%M"),
                "sla_status": "on_track",
            },
            {
                "id": "INC00451245",
                "short_description": "East Herts ANPR camera misreads",
                "assigned_to": "Tristan",
                "workstream": "CWT",
                "priority": "medium",
                "state": "In Progress",
                "opened": (now - timedelta(days=1, hours=3)).strftime("%d/%m %H:%M"),
                "sla_status": "on_track",
            },
            {
                "id": "INC00451310",
                "short_description": "NEOPS config sync failure - batch 47",
                "assigned_to": "Rob",
                "workstream": "NEOPS",
                "priority": "high",
                "state": "In Progress",
                "opened": (now - timedelta(hours=2)).strftime("%d/%m %H:%M"),
                "sla_status": "on_track",
            },
            {
                "id": "INC00451298",
                "short_description": "NEOPS terminal firmware update - Cambridgeshire",
                "assigned_to": "Suna",
                "workstream": "NEOPS",
                "priority": "medium",
                "state": "In Progress",
                "opened": (now - timedelta(days=2)).strftime("%d/%m %H:%M"),
                "sla_status": "at_risk",
            },
            {
                "id": "INC00451315",
                "short_description": "NEOPS display fault - National Trust batch",
                "assigned_to": "Sofia",
                "workstream": "NEOPS",
                "priority": "low",
                "state": "On Hold",
                "opened": (now - timedelta(days=3)).strftime("%d/%m %H:%M"),
                "sla_status": "on_track",
            },
            {
                "id": "INC00451320",
                "short_description": "West Suffolk banking file upload failure",
                "assigned_to": "Joe",
                "workstream": "Back Office",
                "priority": "high",
                "state": "In Progress",
                "opened": (now - timedelta(hours=3)).strftime("%d/%m %H:%M"),
                "sla_status": "on_track",
            },
            {
                "id": "INC00451288",
                "short_description": "API gateway timeout - payment processing",
                "assigned_to": "Anna",
                "workstream": "Back Office",
                "priority": "medium",
                "state": "In Progress",
                "opened": (now - timedelta(days=1, hours=6)).strftime("%d/%m %H:%M"),
                "sla_status": "on_track",
            },
            {
                "id": "INC00451322",
                "short_description": "France commissioning - connectivity issue",
                "assigned_to": "",
                "workstream": "Back Office",
                "priority": "medium",
                "state": "New",
                "opened": (now - timedelta(minutes=45)).strftime("%d/%m %H:%M"),
                "sla_status": "on_track",
            },
        ]

        # Build per-member summary
        member_summary = []
        for m in members:
            member_tickets = [t for t in tickets if t["assigned_to"] == m["name"]]
            member_summary.append({
                "name": m["name"],
                "workstream": m["workstream"],
                "active_tickets": len(member_tickets),
                "tickets": member_tickets,
            })

        unassigned = [t for t in tickets if not t["assigned_to"]]
        critical = [t for t in tickets if t["priority"] == "critical"]
        at_risk = [t for t in tickets if t["sla_status"] == "at_risk"]

        return {
            "tickets": tickets,
            "member_summary": member_summary,
            "alerts": {
                "unassigned": len(unassigned),
                "critical": len(critical),
                "at_risk_sla": len(at_risk),
            },
            "summary": {
                "total": len(tickets),
                "new": sum(1 for t in tickets if t["state"] == "New"),
                "in_progress": sum(1 for t in tickets if t["state"] == "In Progress"),
                "on_hold": sum(1 for t in tickets if t["state"] == "On Hold"),
            },
        }
