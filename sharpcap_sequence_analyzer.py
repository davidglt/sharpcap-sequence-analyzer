#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyze SharpCap session logs and create JSON, CSV and text reports."""

from __future__ import annotations

import csv
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIRECTORY / "sharpcap_sequence_analyzer.properties"
REPORTS_DIRECTORY = SCRIPT_DIRECTORY / "reports"

LOG_FILENAME_PATTERN = re.compile(
    r"^Log_(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<hour>\d{2})_(?P<minute>\d{2})_(?P<second>\d{2})"
    r"-\d+\.log$",
    re.IGNORECASE,
)

RECORD_PATTERN = re.compile(
    r"^(?P<level>Trace|Debug|Info|Warning|Error|Fatal)\s*\t"
    r"\s*(?P<clock>\d{2}:\d{2}:\d{2}\.\d{1,6})\s*\t"
    r"\s*#?(?P<thread>\d+)\s*\t"
    r"\s*(?P<message>.*)$",
    re.IGNORECASE,
)

TARGET_PATTERN = re.compile(
    r"Creating\s+file\s+name\s+provider\s+for\s+target\s+"
    r"(?P<target>'[^']*'|[^,]+),\s*"
    r"(?P<camera>[^,]+),\s*"
    r"(?P<filter>[^,]+),\s*"
    r"(?P<frame_type>Light|Dark|Flat|Bias)\b",
    re.IGNORECASE,
)

FITS_PATTERN = re.compile(
    r"\bInitializing\s+FitsFileWriter\s+at\s+"
    r"(?P<width>\d+)x(?P<height>\d+)x"
    r"(?P<planes>\d+)x(?P<bits>\d+)bits,\s*"
    r"(?P<bayer>[^,]+),.*?\bfor\s+"
    r"(?P<camera>.+?)\s+in\s+void\b",
    re.IGNORECASE,
)

EXPOSURE_START_PATTERN = re.compile(
    r"\bStarting\s+ZWO\s+Exposure\s+of\s+(?P<milliseconds>\d+)ms\b",
    re.IGNORECASE,
)
EXPOSURE_END_PATTERN = re.compile(
    r"\bFinished\s+ZWO\s+Exposure\s+of\s+(?P<milliseconds>\d+)ms,\s*"
    r"gotFrame\s+(?P<success>True|False)\b",
    re.IGNORECASE,
)
CAPTURED_FILE_PATTERN = re.compile(
    r"\bCaptured\s+to\s+(?P<path>.+?\.(?:fits|fit|ser|png|tif|tiff))\b",
    re.IGNORECASE,
)
FRAME_TYPE_PATTERN = re.compile(
    r"\bSet\s+frame\s+type\s+to\s+(?P<frame_type>Light|Dark|Flat|Bias)\b",
    re.IGNORECASE,
)
FILTER_POSITION_PATTERN = re.compile(
    r"\bMove\s+filter\s+wheel\s+to\s+position\s+(?P<filter>[A-Za-z0-9_-]+)"
    r"(?:\s+in\s+void|\s*$)",
    re.IGNORECASE,
)
CAPTURE_SEQUENCE_START_PATTERN = re.compile(
    r"\bSequencer\s+(?::\s*)?Starting\s+(?::\s*)?"
    r"Capture\s+(?P<count>\d+)\s+still\s+frames\b",
    re.IGNORECASE,
)
CAPTURE_SEQUENCE_END_PATTERN = re.compile(
    r"\bSequencer\s+(?::\s*)?(?:Completed|Cancelled)\s+(?::\s*)?"
    r"Capture\s+(?P<count>\d+)\s+still\s+frames\b",
    re.IGNORECASE,
)
PROGRESS_PATTERN = re.compile(
    r"Progress\s+completed\s+(?P<completed>\d+)\s+of\s+(?P<total>\d+)\s+"
    r"Capture\s+(?P<planned>\d+)\s+still\s+frames\s+"
    r"guiding\s+required\s+(?P<guiding>True|False)",
    re.IGNORECASE,
)

AUTOFOCUS_DESCRIPTION_PATTERN = re.compile(
    r"\bAutofocus\s+"
    r"(?:(?:from\s+offset\s+(?P<offset_min>-?\d+)\s+to\s+(?P<offset_max>-?\d+))|"
    r"(?:between\s+(?P<range_min>-?\d+)\s+and\s+(?P<range_max>-?\d+)))\s+"
    r"with\s+(?P<steps>\d+)\s+steps?\s+allowing\s+for\s+backlash\s+up\s+to\s+"
    r"(?P<backlash>\d+)",
    re.IGNORECASE,
)
AUTOFOCUS_STEP_START_PATTERN = re.compile(
    r"\bSequencer\s+(?::\s*)?Starting\s+(?::\s*)?"
    r"(?P<description>Autofocus\b.*?)(?:\s+in\s+|\s*$)",
    re.IGNORECASE,
)
AUTOFOCUS_STEP_END_PATTERN = re.compile(
    r"\bSequencer\s+(?::\s*)?Completed\s+(?::\s*)?Autofocus\b",
    re.IGNORECASE,
)
FOCUS_MEASUREMENT_PATTERN = re.compile(
    r"\bFocus\s+measurement\s+of\s+(?P<score>[\d.,]+)\s+at\s+"
    r"(?P<position>-?\d+).*?\bwhile\s+running\s+step\s+"
    r"(?P<description>Autofocus\b.*?)(?:\s+in\s+|\s*$)",
    re.IGNORECASE,
)
BEST_FIT_PATTERN = re.compile(
    r"\bCurrent\s+best\s+fit\s+is\s+(?P<status>\w+)\s+with\s+best\s+at\s+"
    r"(?P<position>[\d.,]+),\s+confidence\s+(?P<confidence>[\d.,]+),\s+"
    r"based\s+on\s+(?P<points>\d+)\s+points\b",
    re.IGNORECASE,
)
FOCUS_SCAN_RESULT_PATTERN = re.compile(
    r"\bAfter\s+focus\s+scan,\s*best\s+fit\s+gives\s+focus\s+score\s+of\s+"
    r"(?P<score>[\d.,]+)\s+at\s+(?P<position>-?\d+)\s+with\s+graph\s+"
    r"explaining\s+(?P<variance>[\d.,]+)\s*(?:%|percent)?\s+of\s+variance\b",
    re.IGNORECASE,
)
AUTOFOCUS_RESULT_PATTERN = re.compile(
    r"\bAutofocus\s+result\s*:?\s*best\s+focus\s+at\s+(?P<position>[\d.,]+)\s+"
    r"with\s+focuser\s+temperature\s+of\s+(?P<temperature>[-\d.,]+)\s*C\b",
    re.IGNORECASE,
)
AUTOFOCUS_FAILURE_PATTERN = re.compile(
    r"\bAutofocus\s+failed\s*:?\s*(?P<reason>.+?)(?:\s+in\s+|\s*$)",
    re.IGNORECASE,
)

DITHER_STEP_START_PATTERN = re.compile(
    r"\bSequencer\s+(?::\s*)?Starting\s+(?::\s*)?"
    r"Request\s+a\s+single\s+dither\s+from\s+Guiding\s+Application\b",
    re.IGNORECASE,
)
DITHER_STEP_END_PATTERN = re.compile(
    r"\bSequencer\s+(?::\s*)?Completed\s+(?::\s*)?"
    r"Request\s+a\s+single\s+dither\s+from\s+Guiding\s+Application\b",
    re.IGNORECASE,
)
DITHER_PATTERN = re.compile(
    r"\bRequesting\s+dither\s+from\s+PHD2\s+"
    r"(?P<pixels>[\d.,]+),\s*(?P<ra_only>True|False),\s*"
    r"(?P<settle_pixels>[\d.,]+),\s*(?P<settle_min>[\d.,]+),\s*"
    r"(?P<settle_max>[\d.,]+)\b",
    re.IGNORECASE,
)

THERMAL_START_PATTERN = re.compile(
    r"\bThermal\s+correction\s*:?\s*starting\s+"
    r"(?P<script>run[_-]?focus(?:[_-]?guide)?\.bat)\b",
    re.IGNORECASE,
)
THERMAL_FINISH_PATTERN = re.compile(
    r"\bThermal\s+correction\s*:?\s*finished\s+"
    r"(?P<script>run[_-]?focus(?:[_-]?guide)?\.bat)\b",
    re.IGNORECASE,
)
THERMAL_COMMAND_PATTERN = re.compile(
    r"\bRun\s+(?P<command>C[-_]?focus[-_]?sequencerfocus(?:[-_]?guide)?\.bat)"
    r"(?:\s+with\s+parameters\s*(?P<parameters>.*?))?\s+and\s+wait\s+for\s+it\s+to\s+exit\b",
    re.IGNORECASE,
)

FOCUS_SEQUENCER_RECORD_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\|\s+"
    r"(?P<level>START|INFO|SKIP|ERROR|WARNING)\s*\|\s*(?P<message>.*)$",
    re.IGNORECASE,
)

FOCUS_SEQUENCER_START_PATTERN = re.compile(
    r"\btube=(?P<tube>main|guide)\s*\|\s*"
    r"ref=(?P<reference>.*?)\s*\|\s*"
    r"focus_ref=(?P<focus_ref>-?\d+)\s*\|\s*"
    r"T_ref=(?P<temperature>[-\d.,]+)\s*(?:°|º)?C\s*\|\s*"
    r"TCF=(?P<tcf>[-\d.,]+).*?"
    r"(?:\|\s*filter=(?P<filter>.*?))?"
    r"(?:\|\s*filter_offset=(?P<filter_offset>[+-]?\d+))?"
    r".*?\|\s*backlash=(?P<backlash>\d+)\s*\|\s*"
    r"min_correction=(?P<minimum>\d+)",
    re.IGNORECASE,
)

FOCUS_SEQUENCER_CALCULATION_PATTERN = re.compile(
    r"\btube=(?P<tube>main|guide)\s*\|\s*"
    r"T=(?P<temperature>[-\d.,]+)\s*(?:°|º)?C\s*\|\s*"
    r"dT=(?P<delta_temperature>[+-]?[\d.,]+)\s*(?:°|º)?C\s*\|\s*"
    r"TCF=(?P<tcf>[-\d.,]+).*?"
    r"(?:\|\s*filter=(?P<filter>.*?))?"
    r"(?:\|\s*filter_offset=(?P<filter_offset>[+-]?\d+))?"
    r"(?:\|\s*base_target=(?P<base_target>-?\d+))?"
    r"\s*\|\s*target=(?P<target>-?\d+)\s*\|\s*"
    r"pos=(?P<position>-?\d+)\s*\|\s*"
    r"correction=(?P<correction>[+-]?\d+)\s*\|\s*"
    r"backlash=(?P<backlash>True|False)",
    re.IGNORECASE,
)

FOCUS_SEQUENCER_FINAL_PATTERN = re.compile(
    r"\bfinal=(?P<position>-?\d+)",
    re.IGNORECASE,
)

FOCUS_SEQUENCER_END_PATTERN = re.compile(
    r"\bEND\s*\|\s*pos=(?P<position>-?\d+|N/A)\s*\|\s*"
    r"reason=(?P<reason>[A-Za-z0-9_-]+)",
    re.IGNORECASE,
)

FOCUS_SEQUENCER_UPDATE_OK_PATTERN = re.compile(
    r"\bUPDATE\s+OK\b.*?\btube=(?P<tube>main|guide)\b",
    re.IGNORECASE,
)

FOCUS_SEQUENCER_UPDATE_FAILED_PATTERN = re.compile(
    r"\bUPDATE\s+FAILED\b\s*(?:\(rc=(?P<return_code>\d+)\))?\s*:?\s*"
    r"(?P<message>.*)$",
    re.IGNORECASE,
)

MERIDIAN_LIMIT_PATTERN = re.compile(
    r"\bStop\s+running\s+these\s+steps\s+when\s+(?P<degrees>[\d.,]+)\s+"
    r"degrees\s+from\s+the\s+meridian\b",
    re.IGNORECASE,
)
MERIDIAN_FLIP_START_PATTERN = re.compile(
    r"\bSequencer\s+(?::\s*)?Starting\s+(?::\s*)?"
    r"Meridian\s+flip\s+the\s+mount(?:\s+experimental)?\b",
    re.IGNORECASE,
)
MERIDIAN_FLIP_COMPLETE_PATTERN = re.compile(
    r"\bSequencer\s+(?::\s*)?Completed\s+(?::\s*)?"
    r"Meridian\s+flip\s+the\s+mount(?:\s+experimental)?\b",
    re.IGNORECASE,
)
MERIDIAN_WAIT_PATTERN = re.compile(
    r"\bmount\s+is\s+(?:still\s+)?approaching\s+the\s+meridian,\s+"
    r"waiting\s+(?P<minutes>[\d.,]+)\s+minutes\b",
    re.IGNORECASE,
)
SAVED_COORDINATES_PATTERN = re.compile(
    r"\bSaving\s+mount\s+co-ordinates\s+of\s+"
    r"RA(?P<ra>\d{6}(?:[,.]\d+)?),?\s*Dec(?P<dec>[+-]?\d{6}(?:[,.]\d+)?)\b",
    re.IGNORECASE,
)
MERIDIAN_CAPTURE_CANCEL_PATTERN = re.compile(
    r"\bMount\s+at\s+hour\s+angle\s+of\s+(?P<hour_angle>[^,]+),\s*"
    r"which\s+is\s+within\s+(?P<degrees>[\d.,]+)\s+degrees\s+of\s+the\s+meridian\b",
    re.IGNORECASE,
)

NON_ASTRONOMICAL_TARGETS = {"", "capture", "preview", "none", "light", "dark", "flat", "bias"}


def read_properties(path: Path) -> dict[str, str]:
    if not path.exists():
        example = path.with_name(f"{path.name}.example")
        raise FileNotFoundError(f"Configuration file not found: {path}. Copy {example.name} to {path.name} first.")
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def find_latest_log(log_directory: Path) -> Path:
    if not log_directory.exists():
        raise FileNotFoundError(f"SharpCap log directory does not exist: {log_directory}")
    if not log_directory.is_dir():
        raise NotADirectoryError(f"Configured path is not a directory: {log_directory}")
    logs = [path for path in log_directory.rglob("Log_*.log") if path.is_file()]
    if not logs:
        raise FileNotFoundError(f"No Log_*.log files found under: {log_directory}")
    dated_logs: list[tuple[datetime, Path]] = []
    undated_logs: list[Path] = []
    for path in logs:
        try:
            dated_logs.append((parse_filename_datetime(path), path))
        except ValueError:
            undated_logs.append(path)
    if dated_logs:
        return max(dated_logs, key=lambda item: (item[0], item[1].stat().st_mtime))[1]
    return max(undated_logs, key=lambda path: path.stat().st_mtime)


def read_log_lines(log_file: Path) -> list[str]:
    return log_file.read_text(encoding="utf-8", errors="replace").splitlines()


def parse_filename_datetime(log_file: Path) -> datetime:
    match = LOG_FILENAME_PATTERN.match(log_file.name)
    if match is None:
        raise ValueError(f"Unsupported SharpCap log filename: {log_file.name}")
    return datetime.strptime(
        f"{match.group('date')} {match.group('hour')}:{match.group('minute')}:{match.group('second')}",
        "%Y-%m-%d %H:%M:%S",
    )


def parse_record(line: str) -> tuple[str, str | None, str | None, str]:
    text = line.lstrip("\ufeff").rstrip()
    match = RECORD_PATTERN.match(text)
    if match is None:
        return "info", None, None, text.strip()
    return match.group("level").lower(), match.group("clock"), match.group("thread"), match.group("message").strip()


def parse_timestamp(session_start: datetime, clock_time: str, previous: datetime | None) -> datetime:
    event_time = datetime.strptime(clock_time, "%H:%M:%S.%f").time()
    if previous is None:
        return datetime.combine(session_start.date(), event_time)
    timestamp = datetime.combine(previous.date(), event_time)
    if timestamp < previous and (previous - timestamp).total_seconds() > 12 * 3600:
        timestamp += timedelta(days=1)
    return timestamp


def to_number(value: str) -> float:
    return float(value.replace(",", "."))


def to_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def elapsed_seconds(start: datetime | None, end: datetime | None) -> float | None:
    return None if start is None or end is None else (end - start).total_seconds()


def elapsed_text(seconds: float | None) -> str:
    if seconds is None:
        return ""
    total = max(0, int(seconds))
    hours, remaining = divmod(total, 3600)
    minutes, secs = divmod(remaining, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def add_unique(values: list[Any], value: Any) -> None:
    if value is not None and value != "" and value not in values:
        values.append(value)


def clean_target(value: str) -> str | None:
    target = value.strip().strip("'").strip('"').strip()
    return None if target.lower() in NON_ASTRONOMICAL_TARGETS else target or None


def thermal_bucket_key(value: str) -> str:
    return "guide_telescope" if "guide" in value.lower().replace("-", "_") else "main_telescope"


def format_compact_coordinate(value: str, coordinate_type: str) -> str:
    normalized = value.replace(",", ".").strip()
    sign = ""
    if coordinate_type == "dec" and normalized[:1] in {"+", "-"}:
        sign, normalized = normalized[0], normalized[1:]
    whole, dot, fraction = normalized.partition(".")
    if len(whole) != 6:
        return value
    if coordinate_type == "ra":
        result = f"{whole[0:2]}:{whole[2:4]}:{whole[4:6]}"
        return f"{result}.{fraction}" if dot else result
    result = f"{sign}{whole[0:2]}°{whole[2:4]}′{whole[4:6]}"
    return f"{result}.{fraction}″" if dot else f"{result}″"


def classify_diagnostic(level: str, message: str, meridian_flip_active: bool) -> tuple[str, str]:
    normalized = message.lower()
    if "basler.pylon" in normalized:
        return "optional_camera_driver", "information"

    if (
        "focal length is not implemented" in normalized
        or "focallength is not implemented" in normalized
    ):
        return "ascom_driver_capability", "information"

    if (
        "single frame capture cancelled" in normalized
        and "operationcanceledexception" in normalized
    ):
        return "expected_capture_cancellation", "expected"

    if "ignoring error from sequencer" in normalized:
        return "sequencer_error_ignored", "information"

    if (
        "did not find a best focus position" in normalized
        or "no best focus position" in normalized
    ):
        return "autofocus_no_solution", "error"

    if (
        "inner exception" in normalized
        and "ascom.notconnectedexception" in normalized
    ):
        return "focuser_connection_detail", "information"

    if (
        "focuser monitor thread failed" in normalized
        or "ascom.notconnectedexception" in normalized
    ):
        return "focuser_connection", "error"    

    if (("within" in normalized and "degrees of the meridian" in normalized) or
            (meridian_flip_active and ("single frame capture cancelled" in normalized or "capture cancelled" in normalized))):
        return "expected_meridian_flip", "expected"
    if any(token in normalized for token in ("dispatcher overload", "ui freeze", "background priority not run")):
        return "ui_dispatcher_delay", "warning"
    if ("guiding lost" in normalized or "guiding stopped" in normalized or "settlefailed" in normalized or
            "settle failed" in normalized or ("phd2" in normalized and "fail" in normalized)):
        return "guiding_recovery", "warning"
    if any(token in normalized for token in ("plate solve failed", "solve failed", "could not solve", "sync failed")):
        return "plate_solving", "error"
    if any(token in normalized for token in ("autofocus failed", "focus scan failed", "no best focus")):
        return "autofocus", "error"
    if any(token in normalized for token in ("capture failed", "camera error", "exposure failed", "gotframe false")):
        return "camera_capture", "error"
    if any(token in normalized for token in ("exception", "stack trace", "unhandled")) or level == "fatal":
        return "software_exception", "critical"
    return ("other_error", "error") if level == "error" else ("other_warning", "warning")


def autofocus_details(description: str) -> dict[str, Any]:
    details: dict[str, Any] = {"description": description, "mode": None, "offset_min": None, "offset_max": None, "range_start": None, "range_end": None, "configured_steps": None, "backlash_steps": None}
    match = AUTOFOCUS_DESCRIPTION_PATTERN.search(description)
    if match is None:
        return details
    details["configured_steps"] = int(match.group("steps"))
    details["backlash_steps"] = int(match.group("backlash"))
    if match.group("offset_min") is not None:
        details.update({"mode": "offset", "offset_min": int(match.group("offset_min")), "offset_max": int(match.group("offset_max"))})
    else:
        details.update({"mode": "range", "range_start": int(match.group("range_min")), "range_end": int(match.group("range_max"))})
    return details


def new_autofocus(timestamp: datetime, description: str, filter_name: str | None, exposure_seconds: float | None) -> dict[str, Any]:
    return {"started_at": to_iso(timestamp), "completed_at": None, "duration_seconds": None, "duration": "", "status": "running", "filter": filter_name, "exposure_seconds": exposure_seconds, **autofocus_details(description), "measurements": [], "best_fit": None, "scan_result": None, "result": None, "failure_reason": None}


def close_autofocus(run: dict[str, Any], timestamp: datetime, status: str | None = None) -> None:
    run["completed_at"] = to_iso(timestamp)
    if status is not None:
        run["status"] = status
    elif run["status"] == "running":
        run["status"] = "success" if run["result"] else "completed_without_result"
    seconds = elapsed_seconds(datetime.fromisoformat(run["started_at"]), timestamp)
    run["duration_seconds"] = seconds
    run["duration"] = elapsed_text(seconds)


def new_dither(timestamp: datetime) -> dict[str, Any]:
    return {"started_at": to_iso(timestamp), "settled_at": None, "completed_at": None, "duration_seconds": None, "duration": "", "status": "running", "pixels": None, "ra_only": None, "settle_pixels": None, "settle_min_seconds": None, "settle_max_seconds": None}


def close_dither(run: dict[str, Any], timestamp: datetime, status: str = "completed") -> None:
    run["completed_at"] = to_iso(timestamp)
    run["status"] = status
    seconds = elapsed_seconds(datetime.fromisoformat(run["started_at"]), timestamp)
    run["duration_seconds"] = seconds
    run["duration"] = elapsed_text(seconds)

def new_thermal(timestamp: datetime, script: str) -> dict[str, Any]:
    """Create a SharpCap-recorded thermal-correction launch."""
    return {
        "script": script,
        "command": None,
        "parameters": None,
        "started_at": to_iso(timestamp),
        "finished_at": None,
        "duration_seconds": None,
        "duration": "",
        "status": "running",
        "match_status": "not_checked",
        "focus_sequencer": None,
    }

def close_thermal(run: dict[str, Any], timestamp: datetime) -> None:
    run["finished_at"] = to_iso(timestamp)
    run["status"] = "completed"
    seconds = elapsed_seconds(datetime.fromisoformat(run["started_at"]), timestamp)
    run["duration_seconds"] = seconds
    run["duration"] = elapsed_text(seconds)

def parse_focus_sequencer_timestamp(value: str) -> datetime:
    """Parse a Focus Sequencer log timestamp."""
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def focus_sequencer_log_candidates(
    log_directory: Path,
    session_start: datetime,
    session_end: datetime,
    tube: str,
) -> list[Path]:
    """Return daily Focus Sequencer logs that can overlap a SharpCap session."""
    if not log_directory.exists() or not log_directory.is_dir():
        return []

    suffix = (
        "_focus_sequencer_guide.log"
        if tube == "guide"
        else "_focus_sequencer.log"
    )

    first_day = (session_start - timedelta(days=1)).date()
    last_day = (session_end + timedelta(days=1)).date()
    current_day = first_day
    candidates: list[Path] = []

    while current_day <= last_day:
        path = log_directory / f"{current_day.strftime('%Y%m%d')}{suffix}"
        if path.is_file():
            candidates.append(path)
        current_day += timedelta(days=1)

    return candidates


def new_focus_sequencer_execution(
    timestamp: datetime,
    tube: str,
    log_file: Path,
) -> dict[str, Any]:
    """Create one parsed Focus Sequencer execution."""
    return {
        "tube": tube,
        "focus_sequencer_log": str(log_file),
        "started_at": to_iso(timestamp),
        "completed_at": None,
        "duration_seconds": None,
        "duration": "",
        "status": "running",
        "end_reason": None,
        "reference_timestamp": None,
        "focus_reference_position": None,
        "reference_temperature_celsius": None,
        "temperature_celsius": None,
        "delta_temperature_celsius": None,
        "thermal_coefficient": None,
        "filter": None,
        "filter_offset_steps": None,
        "backlash_setting_steps": None,
        "minimum_correction_steps": None,
        "position_before": None,
        "base_target_position": None,
        "target_position": None,
        "requested_correction_steps": None,
        "backlash_applied": None,
        "position_after": None,
        "update_status": "not_logged",
        "update_errors": [],
        "messages": [],
    }


def close_focus_sequencer_execution(
    execution: dict[str, Any],
    timestamp: datetime,
    reason: str,
) -> None:
    """Finalize one Focus Sequencer execution."""
    execution["completed_at"] = to_iso(timestamp)
    execution["end_reason"] = reason
    execution["status"] = reason
    seconds = elapsed_seconds(
        datetime.fromisoformat(execution["started_at"]),
        timestamp,
    )
    execution["duration_seconds"] = seconds
    execution["duration"] = elapsed_text(seconds)


def parse_focus_sequencer_logs(
    log_directory: Path,
    session_start: datetime,
    session_end: datetime,
    tube: str,
) -> list[dict[str, Any]]:
    """Parse Focus Sequencer blocks from the daily log files for one tube."""
    executions: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for log_file in focus_sequencer_log_candidates(
        log_directory,
        session_start,
        session_end,
        tube,
    ):
        for raw_line in log_file.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines():
            record = FOCUS_SEQUENCER_RECORD_PATTERN.match(raw_line.strip())

            if record is None:
                continue

            timestamp = parse_focus_sequencer_timestamp(
                record.group("timestamp")
            )
            level = record.group("level").upper()
            message = record.group("message").strip()

            start = FOCUS_SEQUENCER_START_PATTERN.search(message)
            if level == "START" and start is not None:
                if current is not None and current["completed_at"] is None:
                    close_focus_sequencer_execution(
                        current,
                        timestamp,
                        "interrupted",
                    )

                detected_tube = start.group("tube").lower()
                if detected_tube != tube:
                    current = None
                    continue

                current = new_focus_sequencer_execution(
                    timestamp,
                    tube,
                    log_file,
                )
                current["reference_timestamp"] = start.group("reference")
                current["focus_reference_position"] = int(
                    start.group("focus_ref")
                )
                current["reference_temperature_celsius"] = to_number(
                    start.group("temperature")
                )
                current["thermal_coefficient"] = to_number(
                    start.group("tcf")
                )
                current["filter"] = (
                    start.group("filter").strip()
                    if start.group("filter")
                    else None
                )
                current["filter_offset_steps"] = (
                    int(start.group("filter_offset"))
                    if start.group("filter_offset")
                    else None
                )
                current["backlash_setting_steps"] = int(
                    start.group("backlash")
                )
                current["minimum_correction_steps"] = int(
                    start.group("minimum")
                )
                executions.append(current)
                continue

            if current is None:
                continue

            current["messages"].append(
                {
                    "timestamp": to_iso(timestamp),
                    "level": level,
                    "message": message,
                }
            )

            if level == "ERROR":
                current["update_errors"].append(message)

            update_ok = FOCUS_SEQUENCER_UPDATE_OK_PATTERN.search(message)
            if update_ok:
                current["update_status"] = "ok"

            update_failed = FOCUS_SEQUENCER_UPDATE_FAILED_PATTERN.search(
                message
            )
            if update_failed:
                current["update_status"] = "failed"
                failure = update_failed.group("message").strip()
                if failure:
                    current["update_errors"].append(failure)

            calculation = FOCUS_SEQUENCER_CALCULATION_PATTERN.search(message)
            if calculation:
                current["temperature_celsius"] = to_number(
                    calculation.group("temperature")
                )
                current["delta_temperature_celsius"] = to_number(
                    calculation.group("delta_temperature")
                )
                current["thermal_coefficient"] = to_number(
                    calculation.group("tcf")
                )
                current["filter"] = (
                    calculation.group("filter").strip()
                    if calculation.group("filter")
                    else current["filter"]
                )
                current["filter_offset_steps"] = (
                    int(calculation.group("filter_offset"))
                    if calculation.group("filter_offset")
                    else current["filter_offset_steps"]
                )
                current["position_before"] = int(
                    calculation.group("position")
                )
                current["base_target_position"] = (
                    int(calculation.group("base_target"))
                    if calculation.group("base_target")
                    else None
                )
                current["target_position"] = int(
                    calculation.group("target")
                )
                current["requested_correction_steps"] = int(
                    calculation.group("correction")
                )
                current["backlash_applied"] = (
                    calculation.group("backlash").lower() == "true"
                )
                final = FOCUS_SEQUENCER_FINAL_PATTERN.search(message)
                if final:
                    current["position_after"] = int(final.group("position"))

            end = FOCUS_SEQUENCER_END_PATTERN.search(message)
            if end:
                position = end.group("position")
                if position != "N/A":
                    current["position_after"] = int(position)

                close_focus_sequencer_execution(
                    current,
                    timestamp,
                    end.group("reason"),
                )
                current = None

    if current is not None and current["completed_at"] is None:
        close_focus_sequencer_execution(
            current,
            session_end,
            "unfinished",
        )

    return executions


def match_focus_sequencer_execution(
    thermal_execution: dict[str, Any],
    sequencer_executions: list[dict[str, Any]],
    max_start_delay_seconds: float = 180.0,
) -> dict[str, Any] | None:
    """Return the closest unmatched sequencer block after a SharpCap launch."""
    started_at = thermal_execution.get("started_at")

    if not started_at:
        return None

    sharp_cap_start = datetime.fromisoformat(started_at)
    candidates: list[tuple[float, dict[str, Any]]] = []

    for execution in sequencer_executions:
        if execution.get("_matched"):
            continue

        sequencer_start = datetime.fromisoformat(execution["started_at"])
        delay = (sequencer_start - sharp_cap_start).total_seconds()

        if -30.0 <= delay <= max_start_delay_seconds:
            candidates.append((abs(delay), execution))

    if not candidates:
        return None

    _, selected = min(candidates, key=lambda item: item[0])
    selected["_matched"] = True
    return selected


def enrich_thermal_corrections(
    report: dict[str, Any],
    focus_sequencer_log_directory: Path | None,
) -> None:
    """Join SharpCap thermal launches with Focus Sequencer telemetry."""
    session_start = datetime.fromisoformat(report["session"]["start"])
    session_end = datetime.fromisoformat(report["session"]["end"])

    if focus_sequencer_log_directory is None:
        for correction in report["thermal_corrections"].values():
            for execution in correction["executions"]:
                execution["match_status"] = "focus_sequencer_path_not_configured"
        return

    tube_definitions = {
        "main_telescope": "main",
        "guide_telescope": "guide",
    }

    for key, tube in tube_definitions.items():
        sequencer_executions = parse_focus_sequencer_logs(
            focus_sequencer_log_directory,
            session_start,
            session_end,
            tube,
        )

        correction = report["thermal_corrections"][key]
        correction["focus_sequencer_log_directory"] = str(
            focus_sequencer_log_directory
        )
        correction["focus_sequencer_execution_count"] = len(
            sequencer_executions
        )

        for execution in correction["executions"]:
            matched = match_focus_sequencer_execution(
                execution,
                sequencer_executions,
            )

            if matched is None:
                execution["match_status"] = "no_matching_focus_sequencer_execution"
                continue

            execution["match_status"] = "matched"
            execution["focus_sequencer"] = {
                key: value
                for key, value in matched.items()
                if key != "_matched"
            }

            for error in matched["update_errors"]:
                report["diagnostics"]["entries"].append(
                    {
                        "line_number": None,
                        "timestamp": matched["started_at"],
                        "level": "error",
                        "thread_id": None,
                        "category": "focus_sequencer_error",
                        "impact": "error",
                        "message": f"{tube}: {error}",
                    }
                )

def create_report(log_file: Path, filename_start: datetime) -> dict[str, Any]:
    return {
        "generated_at": datetime.now().astimezone().isoformat(),
        "source_log": {"path": log_file.name, "name": log_file.name, "size_bytes": log_file.stat().st_size, "filename_session_start": to_iso(filename_start), "encoding": "utf-8"},
        "session": {},
        "capture": {"targets": [], "cameras": [], "filters": [], "frame_types": [], "resolutions": [], "bayer_patterns": [], "science_filters": [], "science_exposure_seconds": [], "science_frames": [], "auxiliary_filters": [], "auxiliary_exposure_seconds": [], "auxiliary_frames": [], "captured_files": [], "science_capture_count": 0},
        "sequence": {"capture_blocks": [], "progress_updates": [], "latest_completed_frames": None, "planned_frames": None, "guiding_required": None, "total_completed_frames": 0, "total_planned_frames": 0},
        "guiding": {"dither_runs": [], "dither_request_count": 0, "dither_total_seconds": 0.0, "dither_total_duration": "", "dither_average_seconds": None, "dither_average_duration": "", "settling_count": 0, "settled_count": 0, "settle_failed_count": 0},
        "focus": {"autofocus_runs": [], "autofocus_total_seconds": 0.0, "autofocus_total_duration": "", "autofocus_average_seconds": None, "autofocus_average_duration": ""},
        "thermal_corrections": {"main_telescope": {"script": "runfocus.bat", "command": "C-focus-sequencerfocus.bat", "executions": []}, "guide_telescope": {"script": "runfocusguide.bat", "command": "C-focus-sequencerfocusguide.bat", "executions": []}},
        "meridian_flip": {"configured": False, "configured_stop_distance_degrees": None, "executed": False, "started_at": None, "completed_at": None, "duration_seconds": None, "duration": "", "capture_cancelled_for_meridian": False, "hour_angle_at_cancellation": None, "saved_mount_coordinates": None, "waiting_detected": False, "first_wait_minutes": None, "last_wait_minutes": None, "guiding_stopped": False, "guiding_restarted": False, "plate_solves_after_flip": 0, "operations": []},
        "diagnostics": {"warning_count": 0, "error_count": 0, "fatal_count": 0, "entries": [], "by_category": {}, "impact_counts": {"expected": 0, "information": 0, "warning": 0, "error": 0, "critical": 0}, "relevant_events": []},
    }

def build_report(
    log_file: Path,
    focus_sequencer_log_directory: Path | None = None,
) -> dict[str, Any]:
    filename_start = parse_filename_datetime(log_file)
    lines = read_log_lines(log_file)
    if not any(parse_record(line)[1] is not None for line in lines[:500]):
        raise ValueError("The selected file does not contain recognizable SharpCap records.")

    report = create_report(log_file, filename_start)
    timestamps: list[datetime] = []
    previous_timestamp: datetime | None = None
    current_autofocus: dict[str, Any] | None = None
    current_dither: dict[str, Any] | None = None
    current_capture_block: dict[str, Any] | None = None
    current_thermal: dict[str, dict[str, Any] | None] = {"main_telescope": None, "guide_telescope": None}
    state: dict[str, Any] = {"frame_type": None, "filter": None, "configured_exposure_seconds": None, "capture_block_active": False, "focus_mode_depth": 0, "autofocus_active": False, "last_exposure_is_science": False}
    parsed_records = 0

    for line_number, line in enumerate(lines, start=1):
        level, clock, thread_id, message = parse_record(line)
        if clock is None:
            continue
        timestamp = parse_timestamp(filename_start, clock, previous_timestamp)
        previous_timestamp = timestamp
        timestamps.append(timestamp)
        parsed_records += 1

        diagnostics = report["diagnostics"]
        if level == "warning":
            diagnostics["warning_count"] += 1
        elif level == "error":
            diagnostics["error_count"] += 1
        elif level == "fatal":
            diagnostics["fatal_count"] += 1

        meridian = report["meridian_flip"]
        if level in {"warning", "error", "fatal"}:
            active = meridian["started_at"] is not None and meridian["completed_at"] is None
            category, impact = classify_diagnostic(level, message, active)
            entry = {"line_number": line_number, "timestamp": to_iso(timestamp), "level": level, "thread_id": thread_id, "category": category, "impact": impact, "message": message}
            diagnostics["entries"].append(entry)
            summary = diagnostics["by_category"].setdefault(category, {"count": 0, "impact": impact, "first_timestamp": to_iso(timestamp), "last_timestamp": to_iso(timestamp), "examples": []})
            summary["count"] += 1
            summary["last_timestamp"] = to_iso(timestamp)
            if len(summary["examples"]) < 3:
                summary["examples"].append(message)
            diagnostics["impact_counts"][impact] += 1
            if impact in {"warning", "error", "critical"}:
                diagnostics["relevant_events"].append(entry)

        limit_match = MERIDIAN_LIMIT_PATTERN.search(message)
        if limit_match:
            meridian["configured"] = True
            meridian["configured_stop_distance_degrees"] = to_number(limit_match.group("degrees"))
        cancel_match = MERIDIAN_CAPTURE_CANCEL_PATTERN.search(message)
        if cancel_match:
            meridian["capture_cancelled_for_meridian"] = True
            meridian["hour_angle_at_cancellation"] = cancel_match.group("hour_angle").strip()
        coordinate_match = SAVED_COORDINATES_PATTERN.search(message)
        if coordinate_match:
            raw_ra, raw_dec = coordinate_match.group("ra"), coordinate_match.group("dec")
            meridian["saved_mount_coordinates"] = {"timestamp": to_iso(timestamp), "raw_ra": raw_ra, "raw_dec": raw_dec, "ra": format_compact_coordinate(raw_ra, "ra"), "dec": format_compact_coordinate(raw_dec, "dec")}
        if MERIDIAN_FLIP_START_PATTERN.search(message):
            meridian["executed"] = True
            meridian["started_at"] = to_iso(timestamp)
            meridian["operations"].append({"timestamp": to_iso(timestamp), "event": "meridian_flip_started"})
            if current_capture_block is not None and current_capture_block["ended_at"] is None:
                current_capture_block["ended_at"] = to_iso(timestamp)
                current_capture_block["ended_reason"] = "meridian_flip"
                current_capture_block = None
                state["capture_block_active"] = False
        wait_match = MERIDIAN_WAIT_PATTERN.search(message)
        if wait_match and meridian["started_at"] is not None:
            wait = to_number(wait_match.group("minutes"))
            meridian["waiting_detected"] = True
            if meridian["first_wait_minutes"] is None:
                meridian["first_wait_minutes"] = wait
            meridian["last_wait_minutes"] = wait
        if meridian["started_at"] is not None and "Guiding GuideState changed to Stopped" in message:
            meridian["guiding_stopped"] = True
        if meridian["started_at"] is not None and "Guiding GuideState changed to Guiding" in message:
            meridian["guiding_restarted"] = True
        if meridian["started_at"] is not None and "Plate solve succeeded" in message:
            meridian["plate_solves_after_flip"] += 1
        if MERIDIAN_FLIP_COMPLETE_PATTERN.search(message):
            meridian["executed"] = True
            meridian["completed_at"] = to_iso(timestamp)
            seconds = elapsed_seconds(datetime.fromisoformat(meridian["started_at"]), timestamp)
            meridian["duration_seconds"] = seconds
            meridian["duration"] = elapsed_text(seconds)
            meridian["operations"].append({"timestamp": to_iso(timestamp), "event": "meridian_flip_completed"})

        frame_match = FRAME_TYPE_PATTERN.search(message)
        if frame_match:
            state["frame_type"] = frame_match.group("frame_type").lower()
        filter_match = FILTER_POSITION_PATTERN.search(message)
        if filter_match and re.search(r"\bSequencer\s+(?::\s*)?Completed\s+(?::\s*)?Move\s+filter\s+wheel\s+to\s+position\b", message, re.IGNORECASE):
            state["filter"] = filter_match.group("filter").strip()

        capture_start = CAPTURE_SEQUENCE_START_PATTERN.search(message)
        if capture_start:
            if current_capture_block is not None and current_capture_block["ended_at"] is None:
                current_capture_block["ended_at"] = to_iso(timestamp)
                current_capture_block["ended_reason"] = "superseded"
            phase = "post_meridian_flip" if meridian["executed"] else "pre_meridian_flip"
            current_capture_block = {"block_number": len(report["sequence"]["capture_blocks"]) + 1, "phase": phase, "started_at": to_iso(timestamp), "ended_at": None, "ended_reason": None, "planned_frames": int(capture_start.group("count")), "last_completed_frames": 0, "progress_updates": []}
            report["sequence"]["capture_blocks"].append(current_capture_block)
            state["capture_block_active"] = True
        capture_end = CAPTURE_SEQUENCE_END_PATTERN.search(message)
        if capture_end and current_capture_block is not None:
            current_capture_block["ended_at"] = to_iso(timestamp)
            current_capture_block["ended_reason"] = "completed" if "Completed" in message else "cancelled"
            current_capture_block = None
            state["capture_block_active"] = False

        if AUTOFOCUS_STEP_START_PATTERN.search(message):
            state["autofocus_active"] = True
            state["focus_mode_depth"] += 1
        if AUTOFOCUS_STEP_END_PATTERN.search(message):
            state["autofocus_active"] = False
            state["focus_mode_depth"] = max(0, state["focus_mode_depth"] - 1)
        if re.search(r"\bStarting\s+(?:Refocus|Set\s+exposure/?gain\s+for\s+plate\s+solving\s+and\s+focus)\b", message, re.IGNORECASE):
            state["focus_mode_depth"] += 1
        if re.search(r"\bCompleted\s+(?:Refocus|Set\s+exposure/?gain\s+for\s+plate\s+solving\s+and\s+focus)\b", message, re.IGNORECASE):
            state["focus_mode_depth"] = max(0, state["focus_mode_depth"] - 1)

        target_match = TARGET_PATTERN.search(message)
        if target_match:
            target = clean_target(target_match.group("target"))
            camera, filter_name, frame_type = target_match.group("camera").strip(), target_match.group("filter").strip(), target_match.group("frame_type").strip()
            if target is not None:
                add_unique(report["capture"]["targets"], target)
            add_unique(report["capture"]["cameras"], camera)
            add_unique(report["capture"]["filters"], filter_name)
            add_unique(report["capture"]["frame_types"], frame_type)
            if filter_name.lower() not in {"none", "null"}:
                state["filter"] = filter_name
            state["frame_type"] = frame_type.lower()

        fits_match = FITS_PATTERN.search(message)
        if fits_match:
            add_unique(report["capture"]["resolutions"], f"{fits_match.group('width')}x{fits_match.group('height')}")
            add_unique(report["capture"]["bayer_patterns"], fits_match.group("bayer").strip())
            add_unique(report["capture"]["cameras"], fits_match.group("camera").strip())

        exposure_start = EXPOSURE_START_PATTERN.search(message)
        if exposure_start:
            exposure = int(exposure_start.group("milliseconds")) / 1000
            state["configured_exposure_seconds"] = exposure
            science = state["capture_block_active"] and state["frame_type"] == "light" and state["focus_mode_depth"] == 0 and not state["autofocus_active"] and (state["filter"] or "").lower() != "none"
            event = {"timestamp": to_iso(timestamp), "filter": state["filter"], "frame_type": state["frame_type"], "exposure_seconds": exposure}
            state["last_exposure_is_science"] = science
            if science:
                report["capture"]["science_frames"].append(event)
                add_unique(report["capture"]["science_exposure_seconds"], exposure)
                add_unique(report["capture"]["science_filters"], state["filter"])
            else:
                report["capture"]["auxiliary_frames"].append(event)
                add_unique(report["capture"]["auxiliary_exposure_seconds"], exposure)
                add_unique(report["capture"]["auxiliary_filters"], state["filter"])
        exposure_end = EXPOSURE_END_PATTERN.search(message)
        if exposure_end and state["last_exposure_is_science"] and exposure_end.group("success").lower() == "true":
            report["capture"]["science_capture_count"] += 1
        captured = CAPTURED_FILE_PATTERN.search(message)
        if captured and state["last_exposure_is_science"]:
            report["capture"]["captured_files"].append(captured.group("path").strip())

        progress_match = PROGRESS_PATTERN.search(message)
        if progress_match:
            completed, total, planned = int(progress_match.group("completed")), int(progress_match.group("total")), int(progress_match.group("planned"))
            guiding_required = progress_match.group("guiding").lower() == "true"
            update = {"timestamp": to_iso(timestamp), "completed": completed, "total": total, "planned": planned, "guiding_required": guiding_required}
            report["sequence"]["progress_updates"].append(update)
            if current_capture_block is not None:
                current_capture_block["last_completed_frames"] = completed
                current_capture_block["progress_updates"].append(update)
            report["sequence"].update({"latest_completed_frames": completed, "planned_frames": planned, "guiding_required": guiding_required})

        if DITHER_STEP_START_PATTERN.search(message):
            if current_dither is not None:
                close_dither(current_dither, timestamp, "interrupted")
            current_dither = new_dither(timestamp)
            report["guiding"]["dither_runs"].append(current_dither)
        dither_match = DITHER_PATTERN.search(message)
        if dither_match:
            if current_dither is None:
                current_dither = new_dither(timestamp)
                report["guiding"]["dither_runs"].append(current_dither)
            current_dither.update({"pixels": to_number(dither_match.group("pixels")), "ra_only": dither_match.group("ra_only").lower() == "true", "settle_pixels": to_number(dither_match.group("settle_pixels")), "settle_min_seconds": to_number(dither_match.group("settle_min")), "settle_max_seconds": to_number(dither_match.group("settle_max"))})
        if "Guiding SettleState changed to Settling" in message:
            report["guiding"]["settling_count"] += 1
        if "Guiding SettleState changed to Settled" in message:
            report["guiding"]["settled_count"] += 1
            if current_dither is not None:
                current_dither["settled_at"] = to_iso(timestamp)
        if "SettleFailed" in message:
            report["guiding"]["settle_failed_count"] += 1
        if DITHER_STEP_END_PATTERN.search(message) and current_dither is not None:
            close_dither(current_dither, timestamp)
            current_dither = None

        measurement_match = FOCUS_MEASUREMENT_PATTERN.search(message)
        if measurement_match:
            description = measurement_match.group("description").strip()
            if current_autofocus is None or current_autofocus["description"] != description:
                if current_autofocus is not None:
                    close_autofocus(current_autofocus, timestamp, "interrupted")
                current_autofocus = new_autofocus(timestamp, description, state["filter"], state["configured_exposure_seconds"])
                report["focus"]["autofocus_runs"].append(current_autofocus)
            current_autofocus["measurements"].append({"timestamp": to_iso(timestamp), "score": to_number(measurement_match.group("score")), "position": int(measurement_match.group("position"))})
        best_fit = BEST_FIT_PATTERN.search(message)
        if best_fit and current_autofocus is not None:
            current_autofocus["best_fit"] = {"status": best_fit.group("status"), "position": to_number(best_fit.group("position")), "confidence": to_number(best_fit.group("confidence")), "points": int(best_fit.group("points"))}
        scan_result = FOCUS_SCAN_RESULT_PATTERN.search(message)
        if scan_result and current_autofocus is not None:
            current_autofocus["scan_result"] = {"score": to_number(scan_result.group("score")), "position": int(scan_result.group("position")), "variance_percent": to_number(scan_result.group("variance"))}
        autofocus_result = AUTOFOCUS_RESULT_PATTERN.search(message)
        if autofocus_result:
            if current_autofocus is None:
                current_autofocus = new_autofocus(timestamp, "Autofocus result without captured measurements", state["filter"], state["configured_exposure_seconds"])
                report["focus"]["autofocus_runs"].append(current_autofocus)
            current_autofocus["result"] = {"timestamp": to_iso(timestamp), "best_focus_position": to_number(autofocus_result.group("position")), "focuser_temperature_celsius": to_number(autofocus_result.group("temperature"))}
            close_autofocus(current_autofocus, timestamp)
            current_autofocus = None
            state["autofocus_active"] = False
        autofocus_failure = AUTOFOCUS_FAILURE_PATTERN.search(message)
        if autofocus_failure and current_autofocus is not None:
            current_autofocus["failure_reason"] = autofocus_failure.group("reason").strip()
            close_autofocus(current_autofocus, timestamp, "failed")
            current_autofocus = None
            state["autofocus_active"] = False

        thermal_start = THERMAL_START_PATTERN.search(message)
        if thermal_start:
            script = thermal_start.group("script")
            key = thermal_bucket_key(script)
            if current_thermal[key] is None:
                current_thermal[key] = new_thermal(timestamp, script)
                report["thermal_corrections"][key]["executions"].append(current_thermal[key])
        thermal_command = THERMAL_COMMAND_PATTERN.search(message)
        if thermal_command:
            command = thermal_command.group("command")
            key = thermal_bucket_key(command)
            if current_thermal[key] is None:
                script = "runfocusguide.bat" if key == "guide_telescope" else "runfocus.bat"
                current_thermal[key] = new_thermal(timestamp, script)
                report["thermal_corrections"][key]["executions"].append(current_thermal[key])
            current_thermal[key]["command"] = command
            parameters = thermal_command.group("parameters")
            if parameters is not None:
                current_thermal[key]["parameters"] = parameters.strip() or None
        thermal_finish = THERMAL_FINISH_PATTERN.search(message)
        if thermal_finish:
            key = thermal_bucket_key(thermal_finish.group("script"))
            if current_thermal[key] is not None:
                close_thermal(current_thermal[key], timestamp)
                current_thermal[key] = None

    if parsed_records == 0:
        raise ValueError("No valid SharpCap records were parsed.")
    if current_capture_block is not None:
        current_capture_block["ended_at"] = to_iso(timestamps[-1])
        current_capture_block["ended_reason"] = "session_end"
    if current_autofocus is not None:
        close_autofocus(current_autofocus, timestamps[-1], "unfinished")
    if current_dither is not None:
        close_dither(current_dither, timestamps[-1], "unfinished")
    for execution in current_thermal.values():
        if execution is not None:
            execution["status"] = "unfinished"

    session_start, session_end = min(timestamps), max(timestamps)
    report["session"] = {"start": to_iso(session_start), "end": to_iso(session_end), "duration_seconds": elapsed_seconds(session_start, session_end), "duration": elapsed_text(elapsed_seconds(session_start, session_end)), "parsed_record_count": parsed_records}
    capture = report["capture"]
    capture["captured_file_count"] = len(capture["captured_files"])
    capture["captured_files"] = capture["captured_files"][-100:]
    capture["science_frame_event_count"] = len(capture["science_frames"])
    capture["auxiliary_frame_event_count"] = len(capture["auxiliary_frames"])

    sequence = report["sequence"]
    sequence["progress_update_count"] = len(sequence["progress_updates"])
    sequence["progress_updates"] = sequence["progress_updates"][-100:]
    sequence["total_completed_frames"] = sum(block["last_completed_frames"] for block in sequence["capture_blocks"])
    sequence["total_planned_frames"] = sum(block["planned_frames"] for block in sequence["capture_blocks"])

    guiding = report["guiding"]
    dither_durations = [run["duration_seconds"] for run in guiding["dither_runs"] if run.get("duration_seconds") is not None]
    dither_total = sum(dither_durations)
    dither_average = dither_total / len(dither_durations) if dither_durations else None
    guiding.update({"dither_request_count": len(guiding["dither_runs"]), "dither_total_seconds": dither_total, "dither_total_duration": elapsed_text(dither_total), "dither_average_seconds": dither_average, "dither_average_duration": elapsed_text(dither_average)})

    focus = report["focus"]
    autofocus_durations = [run["duration_seconds"] for run in focus["autofocus_runs"] if run.get("duration_seconds") is not None]
    autofocus_total = sum(autofocus_durations)
    autofocus_average = autofocus_total / len(autofocus_durations) if autofocus_durations else None
    focus.update({"autofocus_run_count": len(focus["autofocus_runs"]), "autofocus_total_seconds": autofocus_total, "autofocus_total_duration": elapsed_text(autofocus_total), "autofocus_average_seconds": autofocus_average, "autofocus_average_duration": elapsed_text(autofocus_average)})

    for correction in report["thermal_corrections"].values():
        correction["execution_count"] = len(correction["executions"])
    enrich_thermal_corrections(
        report,
        focus_sequencer_log_directory,
    )
    return report


def build_focus_rows(report: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for run in report["focus"]["autofocus_runs"]:
        result, scan, measurements = run.get("result") or {}, run.get("scan_result") or {}, run.get("measurements") or []
        if run["mode"] == "offset":
            parameters = f"Offset {run['offset_min']}..{run['offset_max']}; {run['configured_steps']} steps; backlash {run['backlash_steps']}"
        elif run["mode"] == "range":
            parameters = f"Range {run['range_start']}..{run['range_end']}; {run['configured_steps']} steps; backlash {run['backlash_steps']}"
        else:
            parameters = run["description"]
        rows.append({"timestamp": run["started_at"] or "", "source": "SharpCap autofocus", "status": run["status"] or "", "filter": run.get("filter") or "", "exposure_seconds": str(run.get("exposure_seconds") or ""), "parameters": parameters, "start_position": str(measurements[0]["position"] if measurements else ""), "best_position": str(result.get("best_focus_position") or scan.get("position") or ""), "final_position": str(measurements[-1]["position"] if measurements else ""), "temperature_celsius": str(result.get("focuser_temperature_celsius") or ""), "focus_score": str(scan.get("score") or ""), "variance_percent": str(scan.get("variance_percent") or ""), "duration": run["duration"] or "", "tube": "main", "match_status": "", "reference_temperature_celsius": "", "delta_temperature_celsius": "", "thermal_coefficient": "", "filter_offset_steps": "", "requested_correction_steps": "", "backlash_applied": "", "update_status": "", "end_reason": "", "focus_sequencer_log": "",})
    labels = {"main_telescope": "C8 thermal correction", "guide_telescope": "ED50 thermal correction"}
    for key, label in labels.items():
        correction = report["thermal_corrections"][key]
        
        for execution in correction["executions"]:
            command = execution["command"] or correction["command"]
            telemetry = execution.get("focus_sequencer") or {}

            rows.append({
                "timestamp": execution["started_at"] or "",
                "source": label,
                "status": telemetry.get("end_reason") or execution["status"] or "",
                "filter": telemetry.get("filter") or "",
                "exposure_seconds": "",
                "parameters": (
                    f"{command} {execution['parameters'] or ''}".strip()
                ),
                "start_position": str(
                    telemetry.get("position_before") or ""
                ),
                "best_position": str(
                    telemetry.get("target_position") or ""
                ),
                "final_position": str(
                    telemetry.get("position_after") or ""
                ),
                "temperature_celsius": str(
                    telemetry.get("temperature_celsius") or ""
                ),
                "focus_score": "",
                "variance_percent": "",
                "duration": telemetry.get("duration") or execution["duration"] or "",
                "tube": telemetry.get("tube") or (
                    "guide" if key == "guide_telescope" else "main"
                ),
                "match_status": execution.get("match_status") or "",
                "reference_temperature_celsius": str(
                    telemetry.get("reference_temperature_celsius") or ""
                ),
                "delta_temperature_celsius": str(
                    telemetry.get("delta_temperature_celsius") or ""
                ),
                "thermal_coefficient": str(
                    telemetry.get("thermal_coefficient") or ""
                ),
                "filter_offset_steps": str(
                    telemetry.get("filter_offset_steps") or ""
                ),
                "requested_correction_steps": str(
                    telemetry.get("requested_correction_steps") or ""
                ),
                "backlash_applied": str(
                    telemetry.get("backlash_applied")
                    if telemetry.get("backlash_applied") is not None
                    else ""
                ),
                "update_status": telemetry.get("update_status") or "",
                "end_reason": telemetry.get("end_reason") or "",
                "focus_sequencer_log": telemetry.get(
                    "focus_sequencer_log",
                    "",
                ),
            })

    return sorted(rows, key=lambda row: row["timestamp"])


def write_reports(
    report: dict[str, Any],
    reports_directory: Path = REPORTS_DIRECTORY,
) -> tuple[Path, Path, Path]:
    reports_directory.mkdir(parents=True, exist_ok=True)
    suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = reports_directory / f"sharpcap_session_report_{suffix}.json"
    csv_path = reports_directory / f"sharpcap_focus_corrections_{suffix}.csv"
    text_path = reports_directory / f"sharpcap_focus_corrections_{suffix}.txt"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    rows = build_focus_rows(report)
    fields = ["timestamp", "source", "tube", "status", "match_status", "filter", "exposure_seconds", "parameters", "start_position", "best_position", "final_position", "temperature_celsius", "reference_temperature_celsius", "delta_temperature_celsius", "thermal_coefficient", "filter_offset_steps", "requested_correction_steps", "backlash_applied", "update_status", "end_reason", "focus_score", "variance_percent", "duration", "focus_sequencer_log"]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    header = "Timestamp | Source | Tube | Status | Match | Filter | Start | Target | Final | Temp C | Ref Temp C | dT C | TCF | Correction | Backlash | Update | End reason | Duration"
    lines = ["SharpCap Focus Corrections", "=" * 26, "", header, "-" * len(header)]
    for row in rows:
        lines.append(
            " | ".join(
                row.get(field, "")
                for field in [
                    "timestamp",
                    "source",
                    "tube",
                    "status",
                    "match_status",
                    "filter",
                    "start_position",
                    "best_position",
                    "final_position",
                    "temperature_celsius",
                    "reference_temperature_celsius",
                    "delta_temperature_celsius",
                    "thermal_coefficient",
                    "requested_correction_steps",
                    "backlash_applied",
                    "update_status",
                    "end_reason",
                    "duration",
        ]
    )
)
    if not rows:
        lines.append("No autofocus or thermal correction events found.")
    text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, csv_path, text_path


def format_values(values: list[Any], suffix: str = "") -> str:
    return ", ".join(f"{value}{suffix}" for value in values) if values else "Not detected"

def print_thermal_correction_details(
    report: dict[str, Any],
) -> None:
    """Print one concise line for every thermal focus correction."""
    labels = {
        "main_telescope": "Main tube thermal corrections",
        "guide_telescope": "Guide tube thermal corrections",
    }

    for key, heading in labels.items():
        executions = report["thermal_corrections"][key]["executions"]

        print(heading + ":")

        if not executions:
            print("  None")
            continue

        for execution in executions:
            telemetry = execution.get("focus_sequencer") or {}
            timestamp = execution.get("started_at") or "unknown"
            clock = timestamp.split("T")[-1] if "T" in timestamp else timestamp
            status = telemetry.get("end_reason") or execution.get("status")
            match_status = execution.get("match_status", "not_checked")

            if not telemetry:
                print(
                    f"  [{clock}] {status}; match={match_status}; "
                    f"script={execution.get('script')}"
                )
                continue

            temperature = telemetry.get("temperature_celsius")
            delta = telemetry.get("delta_temperature_celsius")
            tcf = telemetry.get("thermal_coefficient")
            correction = telemetry.get("requested_correction_steps")
            before = telemetry.get("position_before")
            after = telemetry.get("position_after")
            backlash = telemetry.get("backlash_applied")
            update = telemetry.get("update_status")

            print(
                f"  [{clock}] T={temperature} C; dT={delta} C; "
                f"TCF={tcf}; corr={correction}; "
                f"pos={before}->{after}; backlash={backlash}; "
                f"u={update}; r={status}"
            )

def print_summary(report: dict[str, Any], json_path: Path, csv_path: Path, text_path: Path) -> None:
    capture, sequence, guiding, focus = report["capture"], report["sequence"], report["guiding"], report["focus"]
    thermal, meridian, diagnostics = report["thermal_corrections"], report["meridian_flip"], report["diagnostics"]
    print("SharpCap Session Analyzer")
    print("=" * 30)
    print(f"Log file: {report['source_log']['name']}")
    print(f"Session start: {report['session']['start']}")
    print(f"Session end: {report['session']['end']}")
    print(f"Duration: {report['session']['duration']}")
    print(f"Target: {format_values(capture['targets'])}")
    print(f"Camera: {format_values(capture['cameras'])}")
    print(f"Light frame type(s): {format_values(capture['frame_types'])}")
    print(f"Light filter(s): {format_values(capture['science_filters'])}")
    print(f"Light exposure(s): {format_values(capture['science_exposure_seconds'], ' s')}")
    print(f"Focus/auxiliary filter(s): {format_values(capture['auxiliary_filters'])}")
    print(f"Focus/auxiliary exposure(s): {format_values(capture['auxiliary_exposure_seconds'], ' s')}")
    print(f"Science exposure events: {capture['science_frame_event_count']}")
    print(f"Auxiliary exposure events: {capture['auxiliary_frame_event_count']}")
    print("Capture progress:")
    for block in sequence["capture_blocks"]:
        phase = block["phase"].replace("_", " ").title()
        print(f"  {phase}: {block['last_completed_frames']}/{block['planned_frames']} ({block['ended_reason'] or 'active'})")
    print(f"Total Light frames completed: {sequence['total_completed_frames']}")
    print(f"Dither requests: {guiding['dither_request_count']}")
    print(f"Total dither time: {guiding['dither_total_duration'] or '00:00:00'}")
    print(f"Average dither time: {guiding['dither_average_duration'] or '00:00:00'}")
    print(f"Autofocus runs: {focus['autofocus_run_count']}")
    print(f"Total autofocus time: {focus['autofocus_total_duration'] or '00:00:00'}")
    print(f"Average autofocus time: {focus['autofocus_average_duration'] or '00:00:00'}")
    print(f"Main thermal corrections: {thermal['main_telescope']['execution_count']}")
    print(f"Guide thermal corrections: {thermal['guide_telescope']['execution_count']}")
    print_thermal_correction_details(report)
    print(f"Meridian flip configured: {'yes' if meridian['configured'] else 'no'}")
    print(f"Meridian stop limit: {meridian['configured_stop_distance_degrees'] if meridian['configured_stop_distance_degrees'] is not None else 'Not detected'} degrees")
    print(f"Meridian flip executed: {'yes' if meridian['executed'] else 'no'}")
    if meridian["executed"]:
        print(f"Meridian flip start: {meridian['started_at']}")
        print(f"Meridian flip end: {meridian['completed_at']}")
        print(f"Meridian flip duration: {meridian['duration'] or 'Not detected'}")
        print(f"Capture cancelled at meridian: {'yes' if meridian['capture_cancelled_for_meridian'] else 'no'}")
        saved = meridian["saved_mount_coordinates"]
        if saved:
            print(f"Saved mount coordinates: RA {saved['ra']}, Dec {saved['dec']}")
            print(f"Coordinates saved at: {saved['timestamp']}")
        else:
            print("Saved mount coordinates: Not detected")
        print(f"Guiding stopped for flip: {'yes' if meridian['guiding_stopped'] else 'no'}")
        print(f"Guiding restarted after flip: {'yes' if meridian['guiding_restarted'] else 'no'}")
        print(f"Post-flip plate solves: {meridian['plate_solves_after_flip']}")
    print("Diagnostics:")
    console_errors = [
        event
        for event in diagnostics["entries"]
        if event["impact"] in {"error", "critical"}
    ]

    print("Errors:")

    if console_errors:
        for event in console_errors[:10]:
            timestamp = event.get("timestamp") or "unknown"
            clock = timestamp.split("T")[-1] if "T" in timestamp else timestamp

            print(
                f"  - [{clock}] "
                f"{event['level'].upper()} "
                f"{event['category']}: "
                f"{event['message']}"
            )
    else:
        print("  None")
    console_error_count = len(console_errors)
    print(f"Warnings: {diagnostics['warning_count']}")
    print(f"Errors: {console_error_count}")
    print(f"Fatal records: {diagnostics['fatal_count']}")
    print(f"JSON report: {json_path}")
    print(f"Focus corrections CSV: {csv_path}")
    print(f"Focus corrections table: {text_path}")


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze the latest or a selected SharpCap session log."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=CONFIG_PATH,
        help="Path to the properties configuration file.",
    )
    parser.add_argument(
        "--log",
        type=Path,
        help="Specific SharpCap log to analyze instead of selecting the latest one.",
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=REPORTS_DIRECTORY,
        help="Directory where JSON, CSV, and TXT reports are written.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = parse_arguments(argv)
        properties = read_properties(arguments.config)
        configured_path = properties.get("sharpcap.logs.path")
        focus_sequencer_path = properties.get(
            "sharpcap.focus_sequencer.logs.path"
        )
        focus_sequencer_directory = (
            Path(focus_sequencer_path)
            if focus_sequencer_path
            else None
        )
        if not configured_path:
            raise KeyError("Missing required property: sharpcap.logs.path")
        log_file = arguments.log or find_latest_log(Path(configured_path))
        if not log_file.is_file():
            raise FileNotFoundError(f"SharpCap log file does not exist: {log_file}")
        report = build_report(
            log_file,
            focus_sequencer_directory,
        )
        json_path, csv_path, text_path = write_reports(report, arguments.reports_dir)
        print_summary(report, json_path, csv_path, text_path)
        return 0
    except (FileNotFoundError, NotADirectoryError, KeyError, OSError, UnicodeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
