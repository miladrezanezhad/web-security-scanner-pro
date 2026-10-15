#!/usr/bin/env python3
"""
Notifier and Webhook Dispatcher for Web Security Analyzer Pro.
Sends real-time scan summaries and critical alerts to Discord, Slack, and Telegram webhooks.
"""

import json
from typing import Dict, List, Optional
import requests
from loguru import logger


class Notifier:
    """Dispatches scan notifications and alerts to messaging platforms."""

    def __init__(self, config: Dict):
        """
        Initialize the notifier.

        Args:
            config: Configuration dictionary (reporting / alerts / notifications)
        """
        self.config = config
        self.notif_config = config.get('notifications', {})
        self.enabled = self.notif_config.get('enabled', False)
        self.discord_webhook = self.notif_config.get('discord_webhook', '')
        self.slack_webhook = self.notif_config.get('slack_webhook', '')
        self.telegram_bot_token = self.notif_config.get('telegram_bot_token', '')
        self.telegram_chat_id = self.notif_config.get('telegram_chat_id', '')
        self.notify_on_critical_only = self.notif_config.get('critical_only', False)

    def send_scan_summary(self, scan_result) -> Dict[str, bool]:
        """
        Send formatted scan summary to all configured channels.

        Args:
            scan_result: ScanResult object or dictionary

        Returns:
            Dict mapping channel to boolean success status
        """
        if not self.enabled:
            return {}

        if hasattr(scan_result, 'to_dict'):
            data = scan_result.to_dict()
        elif isinstance(scan_result, dict):
            data = scan_result
        else:
            data = getattr(scan_result, '__dict__', {})

        stats = data.get('statistics', {})
        critical_count = stats.get('critical', 0)
        high_count = stats.get('high', 0)

        # Check if we should suppress non-critical notifications
        if self.notify_on_critical_only and (critical_count == 0 and high_count == 0):
            logger.info("Notification skipped: no critical or high severity findings.")
            return {}

        results = {}

        # 1. Dispatch to Discord
        if self.discord_webhook:
            results['discord'] = self._send_discord(data)

        # 2. Dispatch to Slack
        if self.slack_webhook:
            results['slack'] = self._send_slack(data)

        # 3. Dispatch to Telegram
        if self.telegram_bot_token and self.telegram_chat_id:
            results['telegram'] = self._send_telegram(data)

        return results

    def _send_discord(self, data: Dict) -> bool:
        """Send embed alert to Discord webhook."""
        try:
            target = data.get('target_url', 'Unknown')
            stats = data.get('statistics', {})
            critical = stats.get('critical', 0)
            high = stats.get('high', 0)
            color = 0xFF0000 if critical > 0 else (0xFFA500 if high > 0 else 0x00FF00)

            embed = {
                'title': f"🛡️ Scan Completed: {target}",
                'color': color,
                'fields': [
                    {'name': '🔴 Critical', 'value': str(stats.get('critical', 0)), 'inline': True},
                    {'name': '🟠 High', 'value': str(stats.get('high', 0)), 'inline': True},
                    {'name': '🟡 Medium', 'value': str(stats.get('medium', 0)), 'inline': True},
                    {'name': '🟢 Low / Info', 'value': f"{stats.get('low', 0)} / {stats.get('info', 0)}", 'inline': True},
                    {'name': '⏱️ Duration', 'value': f"{data.get('scan_duration', 0):.1f}s", 'inline': True},
                    {'name': '📦 Modules Run', 'value': str(len(data.get('modules_run', []))), 'inline': True},
                ],
                'footer': {'text': 'Web Security Analyzer Pro v3.0'}
            }

            resp = requests.post(self.discord_webhook, json={'embeds': [embed]}, timeout=10)
            return resp.status_code in [200, 204]
        except Exception as e:
            logger.warning(f"Failed to dispatch Discord webhook: {e}")
            return False

    def _send_slack(self, data: Dict) -> bool:
        """Send message card to Slack webhook."""
        try:
            target = data.get('target_url', 'Unknown')
            stats = data.get('statistics', {})
            text = (
                f"*🛡️ Web Security Analyzer Pro - Scan Alert*\n"
                f"*Target:* {target}\n"
                f"*Findings:* 🔴 Critical: {stats.get('critical', 0)} | "
                f"🟠 High: {stats.get('high', 0)} | 🟡 Medium: {stats.get('medium', 0)}\n"
                f"*Total Issues:* {stats.get('total', 0)}"
            )

            resp = requests.post(self.slack_webhook, json={'text': text}, timeout=10)
            return resp.status_code == 200
        except Exception as e:
            logger.warning(f"Failed to dispatch Slack webhook: {e}")
            return False

    def _send_telegram(self, data: Dict) -> bool:
        """Send notification via Telegram Bot API."""
        try:
            target = data.get('target_url', 'Unknown')
            stats = data.get('statistics', {})
            text = (
                f"🛡️ <b>Web Security Analyzer Pro</b>\n"
                f"<b>Target:</b> {target}\n\n"
                f"📊 <b>Summary:</b>\n"
                f"🔴 Critical: {stats.get('critical', 0)}\n"
                f"🟠 High: {stats.get('high', 0)}\n"
                f"🟡 Medium: {stats.get('medium', 0)}\n"
                f"🟢 Low: {stats.get('low', 0)}\n"
                f"⏱ Duration: {data.get('scan_duration', 0):.1f}s"
            )

            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': text,
                'parse_mode': 'HTML'
            }
            resp = requests.post(url, json=payload, timeout=10)
            return resp.status_code == 200
        except Exception as e:
            logger.warning(f"Failed to send Telegram message: {e}")
            return False
