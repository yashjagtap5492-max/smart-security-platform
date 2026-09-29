from collections import Counter
from datetime import datetime, timedelta
import ipaddress
import math

from app.models import LoginEvent


WINDOWS = {
	"burst": timedelta(minutes=15),
	"hour": timedelta(hours=1),
	"day": timedelta(hours=24),
}


def _normalise(value):
	return value.strip().lower() if isinstance(value, str) else value


def _is_public_ip(value):
	if not value:
		return False

	try:
		address = ipaddress.ip_address(value)
	except ValueError:
		return False

	return not (
		address.is_private
		or address.is_loopback
		or address.is_link_local
		or address.is_reserved
		or address.is_unspecified
	)


def _risk_level(score):
	if score >= 80:
		return "CRITICAL"
	if score >= 60:
		return "HIGH"
	if score >= 30:
		return "MEDIUM"
	return "LOW"


def _add_signal(signals, reasons, name, points, reason):
	signals[name] = round(points, 2)
	if points > 0:
		reasons.append(reason)


def analyze_login_risk(user_id, ip_address, device_info=None, now=None):
	"""Return an explainable, bounded login-risk assessment for one user."""
	now = now or datetime.utcnow()
	ip_address = _normalise(ip_address)
	device_info = _normalise(device_info)

	events = LoginEvent.query.filter(
		LoginEvent.user_id == user_id,
		LoginEvent.event_time >= now - WINDOWS["day"],
		LoginEvent.event_time <= now,
	).order_by(LoginEvent.event_time.desc()).all()

	burst_events = [
		event for event in events
		if event.event_time and event.event_time >= now - WINDOWS["burst"]
	]
	hourly_events = [
		event for event in events
		if event.event_time and event.event_time >= now - WINDOWS["hour"]
	]
	failed_events = [event for event in burst_events if not event.success]
	failed_same_ip = [
		event for event in failed_events
		if _normalise(event.ip_address) == ip_address
	]
	successful_events = [event for event in events if event.success]

	known_ips = {
		_normalise(event.ip_address)
		for event in successful_events
		if event.ip_address
	}
	known_devices = {
		_normalise(event.device_info)
		for event in successful_events
		if event.device_info
	}
	distinct_ips = {
		_normalise(event.ip_address)
		for event in events
		if event.ip_address
	}
	distinct_devices = {
		_normalise(event.device_info)
		for event in events
		if event.device_info
	}

	score = 0.0
	reasons = []
	signals = {}
	failure_count = len(failed_events)
	same_ip_failures = len(failed_same_ip)
	burst_count = len(burst_events)
	hourly_count = len(hourly_events)
	failure_ratio = failure_count / burst_count if burst_count else 0.0

	_add_signal(
		signals, reasons, "failed_attempts", min(failure_count * 8, 24),
		"Repeated failed login attempts detected"
	)
	_add_signal(
		signals, reasons, "same_ip_failures", min(same_ip_failures * 5, 20),
		"Repeated failed attempts from the same IP address"
	)
	_add_signal(
		signals, reasons, "failure_ratio", min(failure_ratio * 20, 20),
		"A high proportion of recent login attempts failed"
	)
	_add_signal(
		signals, reasons, "burst_velocity", min(max(burst_count - 4, 0) * 2, 12),
		"Unusually high login activity in the last 15 minutes"
	)
	_add_signal(
		signals, reasons, "hourly_velocity", min(max(hourly_count - 10, 0), 8),
		"Unusually high login activity in the last hour"
	)

	unfamiliar_ip = bool(ip_address and successful_events and ip_address not in known_ips)
	unfamiliar_device = bool(
		device_info and successful_events and device_info not in known_devices
	)
	_add_signal(
		signals, reasons, "new_ip", 12 if unfamiliar_ip else 0,
		"Login from an IP address not seen in successful logins"
	)
	_add_signal(
		signals, reasons, "new_device", 12 if unfamiliar_device else 0,
		"Login from a device not seen in successful logins"
	)
	_add_signal(
		signals, reasons, "public_ip", 3 if _is_public_ip(ip_address) else 0,
		"Login originated from a public IP address"
	)

	diversity_points = min(max(len(distinct_ips) - 2, 0) * 3, 9)
	device_diversity_points = min(max(len(distinct_devices) - 2, 0) * 2, 6)
	_add_signal(
		signals, reasons, "ip_diversity", diversity_points,
		"Multiple source IP addresses were observed recently"
	)
	_add_signal(
		signals, reasons, "device_diversity", device_diversity_points,
		"Multiple devices were observed recently"
	)

	event_types = Counter(
		event.event_type for event in burst_events if event.event_type
	)
	suspicious_event_points = min(
		sum(count for event_type, count in event_types.items()
			if event_type.upper() in {"FAILED_LOGIN", "SUSPICIOUS", "BLOCKED"}) * 4,
		12,
	)
	_add_signal(
		signals, reasons, "event_history", suspicious_event_points,
		"Recent security events indicate suspicious login activity"
	)

	entropy = 0.0
	if burst_events:
		for event in burst_events:
			probability = 1 / burst_count
			entropy -= probability * math.log2(probability)
	_add_signal(
		signals, reasons, "pattern_complexity", min(max(entropy - 2, 0) * 2, 4),
		"Login activity shows a complex source pattern"
	)

	score = min(round(sum(signals.values()), 2), 100.0)
	if not reasons:
		reasons.append("No significant suspicious login behavior detected")

	return {
		"risk_score": score,
		"risk_level": _risk_level(score),
		"reasons": reasons,
		"signals": signals,
		"metadata": {
			"events_last_15_minutes": burst_count,
			"events_last_hour": hourly_count,
			"events_last_24_hours": len(events),
			"failed_events_last_15_minutes": failure_count,
			"same_ip_failures_last_15_minutes": same_ip_failures,
			"distinct_ips_last_24_hours": len(distinct_ips),
			"distinct_devices_last_24_hours": len(distinct_devices),
		},
	}


def calculate_login_risk(user_id, ip_address, device_info=None):
	"""Keep the original scalar API for existing callers."""
	return analyze_login_risk(user_id, ip_address, device_info)["risk_score"]
