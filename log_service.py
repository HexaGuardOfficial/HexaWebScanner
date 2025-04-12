from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum
import asyncio
from collections import deque

class LogLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"

class LogSection(Enum):
    OWASP = "owasp"
    CVE = "cve"
    ZERODAY = "zeroday"
    OTHER = "other"

class LogEntry:
    def __init__(self, message: str, level: LogLevel, section: LogSection, timestamp: Optional[datetime] = None):
        self.message = message
        self.level = level
        self.section = section
        self.timestamp = timestamp or datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message": self.message,
            "level": self.level.value,
            "section": self.section.value,
            "timestamp": self.timestamp.isoformat()
        }

class RealTimeLogService:
    def __init__(self, max_logs_per_section: int = 1000):
        self.max_logs_per_section = max_logs_per_section
        self.logs: Dict[LogSection, deque] = {
            section: deque(maxlen=max_logs_per_section)
            for section in LogSection
        }
        self.subscribers: List[asyncio.Queue] = []

    async def log(self, message: str, level: LogLevel, section: LogSection) -> None:
        """Add a new log entry and notify all subscribers"""
        entry = LogEntry(message, level, section)
        self.logs[section].append(entry)
        
        # Notify all subscribers
        for queue in self.subscribers:
            await queue.put(entry.to_dict())

    def subscribe(self) -> asyncio.Queue:
        """Subscribe to real-time log updates"""
        queue = asyncio.Queue()
        self.subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Unsubscribe from real-time log updates"""
        if queue in self.subscribers:
            self.subscribers.remove(queue)

    def get_section_logs(self, section: LogSection, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get logs for a specific section"""
        logs = list(self.logs[section])
        if limit:
            logs = logs[-limit:]
        return [log.to_dict() for log in logs]

    def get_all_logs(self, limit_per_section: Optional[int] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Get all logs organized by section"""
        return {
            section.value: self.get_section_logs(section, limit_per_section)
            for section in LogSection
        }

    async def clear_logs(self, section: Optional[LogSection] = None) -> None:
        """Clear logs for a specific section or all sections"""
        if section:
            self.logs[section].clear()
        else:
            for section_logs in self.logs.values():
                section_logs.clear()