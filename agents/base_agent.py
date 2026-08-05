from datetime import datetime


class BaseAgent:
    """Base class for all agents. Each agent polls an external service and caches results."""

    def __init__(self, name):
        self.name = name
        self.last_updated = None
        self.status = "idle"
        self.data = {}
        self.error = None

    def poll(self):
        """Fetch latest data from the external service. Subclasses must implement _fetch."""
        try:
            self.status = "polling"
            self.data = self._fetch()
            self.last_updated = datetime.now().strftime("%H:%M:%S")
            self.status = "ok"
            self.error = None
        except Exception as e:
            self.status = "error"
            self.error = str(e)

    def _fetch(self):
        raise NotImplementedError

    def get_status(self):
        return {
            "agent": self.name,
            "status": self.status,
            "last_updated": self.last_updated,
            "error": self.error,
        }

    def get_data(self):
        return self.data
