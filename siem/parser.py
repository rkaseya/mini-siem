import re
from datetime import datetime
from pathlib import Path

HEADER = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<process>[\w\-]+)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<msg>.*)$"
)

IP = r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"

PATTERNS = {
    "ssh_failed": re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from " + IP + r" port (?P<port>\d+)"
    ),
    "ssh_success": re.compile(
        r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from " + IP + r" port (?P<port>\d+)"
    ),
    "ssh_invalid_user": re.compile(
        r"Invalid user (?P<user>\S+) from " + IP + r" port (?P<port>\d+)"
    ),
}


def parse_line(line, year=None):
    # 1. Lire l'en-tête
    header = HEADER.match(line.strip())
    if header is None:
        return None

    # 2. Convertir la date (auth.log ne donne pas l'année)
    if year is None:
        year = datetime.now().year
    timestamp = datetime.strptime(f"{year} {header['ts']}", "%Y %b %d %H:%M:%S")

    # 3. Identifier le type d'événement
    for event_type, pattern in PATTERNS.items():
        match = pattern.search(header["msg"])
        if match:
            event = {
                "timestamp": timestamp,
                "host": header["host"],
                "process": header["process"],
                "event": event_type,
            }
            event.update(match.groupdict())
            event["port"] = int(event["port"])
            return event

    return None


def parse_file(path, year=None):
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line, year)
            if event is not None:
                events.append(event)
    return events


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    events = parse_file(project_root / "samples" / "auth.log", 2026)
    print(len(events))  # doit afficher 44
    print(events[0])