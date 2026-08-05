from datetime import datetime, timedelta
from agents.base_agent import BaseAgent
import config


class ProjectAgent(BaseAgent):

    def __init__(self):
        super().__init__("Project Agent")

    def _fetch(self):
        if config.USE_MOCK_PROJECTS:
            return self._mock_data()
        return self._fetch_projects()

    def _fetch_projects(self):
        # Phase 4: Real Asana + Trello integration
        return self._mock_data()

    def _mock_data(self):
        now = datetime.now()

        projects = [
            {
                "id": "proj_1",
                "title": "Stourhead Car Park - New Install",
                "source": "Asana",
                "category": "New Order",
                "system": "CWT",
                "status": "In Progress",
                "assignee": "Emie",
                "due_date": (now + timedelta(days=14)).strftime("%d/%m/%Y"),
                "priority": "high",
            },
            {
                "id": "proj_2",
                "title": "Cambridge Grand Arcade - Tariff Update",
                "source": "Trello",
                "category": "Change Request",
                "system": "CWT",
                "status": "To Do",
                "assignee": "Jay",
                "due_date": (now + timedelta(days=7)).strftime("%d/%m/%Y"),
                "priority": "medium",
            },
            {
                "id": "proj_3",
                "title": "Guildford Multi-Storey - Terminal Replacement",
                "source": "Asana",
                "category": "CWT/PARKEON",
                "system": "CWT",
                "status": "In Progress",
                "assignee": "Tristan",
                "due_date": (now + timedelta(days=21)).strftime("%d/%m/%Y"),
                "priority": "medium",
            },
            {
                "id": "proj_4",
                "title": "Cambridgeshire NEOPS Rollout Phase 2",
                "source": "Asana",
                "category": "New Order",
                "system": "NEOPS",
                "status": "In Progress",
                "assignee": "Rob",
                "due_date": (now + timedelta(days=30)).strftime("%d/%m/%Y"),
                "priority": "high",
            },
            {
                "id": "proj_5",
                "title": "National Trust - NEOPS Config Update",
                "source": "Trello",
                "category": "Change Request",
                "system": "NEOPS",
                "status": "To Do",
                "assignee": "Suna",
                "due_date": (now + timedelta(days=10)).strftime("%d/%m/%Y"),
                "priority": "low",
            },
            {
                "id": "proj_6",
                "title": "East Herts - NEOPS Emie Integration",
                "source": "Asana",
                "category": "CWT/PARKEON",
                "system": "NEOPS",
                "status": "On Hold",
                "assignee": "Sofia",
                "due_date": (now + timedelta(days=45)).strftime("%d/%m/%Y"),
                "priority": "medium",
            },
            {
                "id": "proj_7",
                "title": "West Suffolk - Banking API Migration",
                "source": "Asana",
                "category": "Change Request",
                "system": "Back Office",
                "status": "In Progress",
                "assignee": "Joe",
                "due_date": (now + timedelta(days=5)).strftime("%d/%m/%Y"),
                "priority": "critical",
            },
            {
                "id": "proj_8",
                "title": "France Commissioning - Payment Gateway",
                "source": "Trello",
                "category": "New Order",
                "system": "Back Office",
                "status": "To Do",
                "assignee": "Anna",
                "due_date": (now + timedelta(days=60)).strftime("%d/%m/%Y"),
                "priority": "medium",
            },
        ]

        # Category breakdown
        categories = {}
        for p in projects:
            cat = p["category"]
            categories[cat] = categories.get(cat, 0) + 1

        # Source breakdown
        sources = {}
        for p in projects:
            src = p["source"]
            sources[src] = sources.get(src, 0) + 1

        return {
            "projects": projects,
            "summary": {
                "total": len(projects),
                "by_category": categories,
                "by_source": sources,
                "in_progress": sum(1 for p in projects if p["status"] == "In Progress"),
                "to_do": sum(1 for p in projects if p["status"] == "To Do"),
                "on_hold": sum(1 for p in projects if p["status"] == "On Hold"),
            },
        }
