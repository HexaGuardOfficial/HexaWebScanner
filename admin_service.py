from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum
from ..config.api_config import APISectionManager
from .db_manager import DatabaseManager
import psutil
import json

class UserRole(Enum):
    FREE = "free"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"
    ADMIN = "admin"

class AdminService:
    def __init__(self):
        self.api_manager = APISectionManager()
        self.db_manager = DatabaseManager()

    async def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get real-time dashboard statistics"""
        try:
            active_scans = await self.db_manager.get_active_scans_count()
            completed_scans = await self.db_manager.get_completed_scans_count()
            failed_scans = await self.db_manager.get_failed_scans_count()
            total_users = await self.db_manager.get_total_users_count()
            premium_users = await self.db_manager.get_users_count_by_role(UserRole.PREMIUM)
            enterprise_users = await self.db_manager.get_users_count_by_role(UserRole.ENTERPRISE)

            return {
                'scans': {
                    'active': active_scans,
                    'completed': completed_scans,
                    'failed': failed_scans,
                    'total': active_scans + completed_scans + failed_scans
                },
                'users': {
                    'total': total_users,
                    'free': total_users - premium_users - enterprise_users,
                    'premium': premium_users,
                    'enterprise': enterprise_users
                },
                'system_health': self._get_system_health(),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}

    def _get_system_health(self) -> Dict[str, Any]:
        """Get system health metrics"""
        return {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent
        }

    async def get_active_scans(self) -> List[Dict[str, Any]]:
        """Get all active scans with details"""
        return await self.db_manager.get_active_scans()

    async def stop_scan(self, scan_id: str) -> bool:
        """Stop an active scan"""
        return await self.db_manager.stop_scan(scan_id)

    async def get_user_list(self, role: Optional[UserRole] = None) -> List[Dict[str, Any]]:
        """Get list of users with optional role filter"""
        return await self.db_manager.get_users(role)

    async def update_user_role(self, user_id: str, new_role: UserRole) -> bool:
        """Update user's role"""
        return await self.db_manager.update_user_role(user_id, new_role)

    async def ban_user(self, user_id: str) -> bool:
        """Ban a user"""
        return await self.db_manager.ban_user(user_id)

    async def unban_user(self, user_id: str) -> bool:
        """Unban a user"""
        return await self.db_manager.unban_user(user_id)

    async def get_api_keys(self) -> Dict[str, List[str]]:
        """Get all API keys by section"""
        return self.api_manager.get_all_keys()

    async def add_api_key(self, section: str, key: str) -> bool:
        """Add a new API key for a section"""
        return self.api_manager.add_key(section, key)

    async def remove_api_key(self, section: str, key: str) -> bool:
        """Remove an API key from a section"""
        return self.api_manager.remove_key(section, key)

    async def update_scan_limits(self, role: UserRole, new_limit: int) -> bool:
        """Update scan limits for a user role"""
        return await self.db_manager.update_scan_limits(role, new_limit)

    async def get_revenue_stats(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get revenue statistics for a date range"""
        try:
            stats = await self.db_manager.get_revenue_stats(start_date, end_date)
            return {
                'total_revenue': stats.get('total', 0),
                'by_plan': {
                    'premium': stats.get('premium', 0),
                    'enterprise': stats.get('enterprise', 0)
                },
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                }
            }
        except Exception as e:
            return {'error': str(e)}

    async def send_announcement(self, message: str, user_roles: Optional[List[UserRole]] = None) -> bool:
        """Send announcement to users"""
        try:
            return await self.db_manager.create_announcement(message, user_roles)
        except Exception:
            return False

    async def get_system_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get system logs"""
        return await self.db_manager.get_system_logs(limit)

    async def backup_database(self) -> str:
        """Create a database backup"""
        try:
            backup_data = await self.db_manager.export_database()
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'backup_{timestamp}.json'
            
            with open(filename, 'w') as f:
                json.dump(backup_data, f)
            
            return filename
        except Exception as e:
            return str(e)

    async def restore_database(self, backup_file: str) -> bool:
        """Restore database from backup"""
        try:
            with open(backup_file, 'r') as f:
                backup_data = json.load(f)
            return await self.db_manager.import_database(backup_data)
        except Exception:
            return False