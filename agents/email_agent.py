from datetime import datetime, timedelta
import imaplib
import email
from email.header import decode_header
from agents.base_agent import BaseAgent
import config


URGENT_KEYWORDS = [
    "urgent", "critical", "down", "offline", "emergency", "asap",
    "failed", "failure", "outage", "alert", "p1", "sev1", "escalat",
]


class EmailAgent(BaseAgent):

    def __init__(self):
        super().__init__("Email Agent")

    def _fetch(self):
        if config.USE_MOCK_EMAIL:
            return self._mock_data()
        return self._fetch_gmail()

    def _fetch_gmail(self):
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(config.GMAIL_ADDRESS, config.GMAIL_APP_PASSWORD)
        mail.select("inbox")

        # Fetch emails from the last 24 hours
        since_date = (datetime.now() - timedelta(days=1)).strftime("%d-%b-%Y")
        status, message_ids = mail.search(None, f'(SINCE "{since_date}")')

        if status != "OK" or not message_ids[0]:
            mail.logout()
            return {"emails": [], "summary": {"total": 0, "unread": 0, "critical": 0, "high": 0}}

        ids = message_ids[0].split()
        # Get the most recent 20 emails
        recent_ids = ids[-20:]

        emails_list = []
        for msg_id in reversed(recent_ids):
            status, msg_data = mail.fetch(msg_id, "(RFC822 FLAGS)")
            if status != "OK":
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            # Parse flags for read/unread
            flags_data = msg_data[0][0].decode() if isinstance(msg_data[0][0], bytes) else str(msg_data[0][0])
            is_read = "\\Seen" in flags_data

            # Decode subject
            subject = self._decode_header(msg["Subject"]) or "(No Subject)"

            # Decode sender
            from_addr = self._decode_header(msg["From"]) or "Unknown"

            # Get date
            date_str = msg["Date"]
            try:
                msg_date = email.utils.parsedate_to_datetime(date_str)
                time_str = msg_date.strftime("%H:%M")
            except Exception:
                time_str = "--:--"

            # Get snippet from body
            snippet = self._get_snippet(msg)

            # Determine priority
            priority = self._classify_priority(subject, from_addr, snippet, msg)

            emails_list.append({
                "id": msg_id.decode(),
                "from": from_addr,
                "subject": subject,
                "snippet": snippet,
                "time": time_str,
                "priority": priority,
                "read": is_read,
            })

        mail.logout()

        critical_count = sum(1 for e in emails_list if e["priority"] == "critical")
        high_count = sum(1 for e in emails_list if e["priority"] == "high")
        unread_count = sum(1 for e in emails_list if not e["read"])

        return {
            "emails": emails_list,
            "summary": {
                "total": len(emails_list),
                "unread": unread_count,
                "critical": critical_count,
                "high": high_count,
            },
        }

    def _decode_header(self, header_value):
        if not header_value:
            return ""
        decoded_parts = decode_header(header_value)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                result.append(part)
        return " ".join(result)

    def _get_snippet(self, msg):
        """Extract a text snippet from the email body."""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        charset = part.get_content_charset() or "utf-8"
                        body = part.get_payload(decode=True).decode(charset, errors="replace")
                    except Exception:
                        body = ""
                    break
        else:
            try:
                charset = msg.get_content_charset() or "utf-8"
                body = msg.get_payload(decode=True).decode(charset, errors="replace")
            except Exception:
                body = ""

        # Clean up and truncate
        body = body.replace("\r\n", " ").replace("\n", " ").strip()
        return body[:200] + "..." if len(body) > 200 else body

    def _classify_priority(self, subject, from_addr, snippet, msg):
        """Classify email priority based on subject, content, and headers."""
        text = (subject + " " + snippet).lower()

        # Check X-Priority header (1=highest, 5=lowest)
        x_priority = msg.get("X-Priority", "")
        if x_priority.startswith("1"):
            return "critical"
        if x_priority.startswith("2"):
            return "high"

        # Check for urgent keywords
        urgent_hits = sum(1 for kw in URGENT_KEYWORDS if kw in text)
        if urgent_hits >= 2:
            return "critical"
        if urgent_hits >= 1:
            return "high"

        return "normal"

    def _mock_data(self):
        now = datetime.now()
        emails = [
            {
                "id": "email_1",
                "from": "operations@cwtglobal.com",
                "subject": "URGENT: Guildford P&D Terminal Offline",
                "snippet": "Terminal 4 at Guildford multi-storey has gone offline. No transactions processing since 06:15...",
                "time": (now - timedelta(minutes=12)).strftime("%H:%M"),
                "priority": "critical",
                "read": False,
            },
            {
                "id": "email_2",
                "from": "servicenow@company.com",
                "subject": "INC00451289 assigned to your team",
                "snippet": "A new incident has been assigned to your team regarding Sunderland barrier fault...",
                "time": (now - timedelta(minutes=35)).strftime("%H:%M"),
                "priority": "high",
                "read": False,
            },
            {
                "id": "email_3",
                "from": "procurement@nationaltrust.org.uk",
                "subject": "RE: New Order - Stourhead Car Park",
                "snippet": "Please find attached the purchase order for 3x CWT terminals for the Stourhead site...",
                "time": (now - timedelta(hours=1, minutes=20)).strftime("%H:%M"),
                "priority": "normal",
                "read": True,
            },
            {
                "id": "email_4",
                "from": "jim.harris@cambridgeshire.gov.uk",
                "subject": "Change Request - Tariff Update Cambridge Grand Arcade",
                "snippet": "Hi Ross, we need the evening tariff updated from 1st May. New rate is £2.50/hr after 6pm...",
                "time": (now - timedelta(hours=2, minutes=5)).strftime("%H:%M"),
                "priority": "normal",
                "read": True,
            },
            {
                "id": "email_5",
                "from": "alerts@monitoring.parkeon.com",
                "subject": "ALERT: Banking file upload failed - West Suffolk",
                "snippet": "The daily banking file for West Suffolk failed to upload at 03:00. Retry attempted at 03:30 also failed...",
                "time": (now - timedelta(hours=3)).strftime("%H:%M"),
                "priority": "high",
                "read": False,
            },
        ]

        critical_count = sum(1 for e in emails if e["priority"] == "critical")
        high_count = sum(1 for e in emails if e["priority"] == "high")
        unread_count = sum(1 for e in emails if not e["read"])

        return {
            "emails": emails,
            "summary": {
                "total": len(emails),
                "unread": unread_count,
                "critical": critical_count,
                "high": high_count,
            },
        }
