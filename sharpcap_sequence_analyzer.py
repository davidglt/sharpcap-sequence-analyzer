#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SharpCap Session Log Analyzer.

Analyzes SharpCap 4.1 logs in padded tab-delimited format:

    Info   <TAB>21:57:04.149905<TAB>#1 <TAB>Starting SharpCap ...
    Debug  <TAB>22:49:12.938713<TAB>#1 <TAB>Sequencer Progress completed ...

Generated output:
- reports/sharpcap_session_report_YYYYMMDD_HHMMSS.json
- reports/sharpcap_focus_corrections_YYYYMMDD_HHMMSS.csv
- reports/sharpcap_focus_corrections_YYYYMMDD_HHMMSS.txt

Required local configuration:
    sharpcap_sequence_analyzer.properties

Required property:
    sharpcap.logs.path=C:\\Users\\your-user\\AppData\\Local\\SharpCap\\logs
"""

from __future__ import annotations

import csv
import json
import re
import sys
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
    r"\bStarting\s+ZWO\s+Exposure\s+of\s+"
    r"(?P<milliseconds>\d+)ms\b",
    re.IGNORECASE,
)

EXPOSURE_END_PATTERN = re.compile(
    r"\bFinished\s+ZWO\s+Exposure\s+of\s+"
    r"(?P<milliseconds>\d+)ms,\s*"
    r"gotFrame\s+(?P<success>True|False)\b",
    re.IGNORECASE,
)

CAPTURED_FILE_PATTERN = re.compile(
    r"\bCaptured\s+to\s+(?P<path>.+?\.(?:fits|fit|ser|png|tif|tiff))\b",
    re.IGNORECASE,
)

FRAME_TYPE_PATTERN = re.compile(
    r"\bSet\s+frame\s+type\s+to\s+"
    r"(?P<frame_type>Light|Dark|Flat|Bias)\b",
    re.IGNORECASE,
)

FILTER_POSITION_PATTERN = re.compile(
    r"\bMove\s+filter\s+wheel\s+to\s+position\s+"
    r"(?P<filter>[A-Za-z0-9_-]+)"
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
    r"\bProgress\s+completed\s+"
    r"(?P<completed>\d+)\s+of\s+(?P<total>\d+)\s+"
    r"Capture\s+(?P<planned>\d+)\s+still\s+frames\s+"
    r"guiding\s+required\s+(?P<guiding>True|False)\b",
    re.IGNORECASE,
)

FOCUS_MODE_START_PATTERN = re.compile(
    r"\b(?:"
    r"Starting\s+Set\s+exposure/?gain\s+for\s+plate\s+solving\s+and\s+focus|"
    r"Starting\s+Autofocus\b|"
    r"Starting\s+Refocus\b"
    r")",
    re.IGNORECASE,
)

FOCUS_MODE_END_PATTERN = re.compile(
    r"\b(?:"
    r"Completed\s+Set\s+exposure/?gain\s+for\s+plate\s+solving\s+and\s+focus|"
    r"Completed\s+Autofocus\b|"
    r"Completed\s+Refocus\b"
    r")",
    re.IGNORECASE,
)

AUTOFOCUS_STEP_START_PATTERN = re.compile(
    r"\bSequencer\s+(?::\s*)?Starting\s+(?::\s*)?"
    r"(?P<description>Autofocus\b.*?)"
    r"(?:\s+in\s+|\s*$)",
    re.IGNORECASE,
)

AUTOFOCUS_STEP_END_PATTERN = re.compile(
    r"\bSequencer\s+(?::\s*)?Completed\s+(?::\s*)?"
    r"Autofocus\b",
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
    r"(?P<pixels>[\d.,]+),\s*"
    r"(?P<ra_only>True|False),\s*"
    r"(?P<settle_pixels>[\d.,]+),\s*"
    r"(?P<settle_min>[\d.,]+),\s*"
    r"(?P<settle_max>[\d.,]+)\b",
    re.IGNORECASE,
)

AUTOFOCUS_DESCRIPTION_PATTERN = re.compile(
    r"\bAutofocus\s+"
    r"(?:(?:from\s+offset\s+(?P<offset_min>-?\d+)\s+to\s+"
    r"(?P<offset_max>-?\d+))|"
    r"(?:between\s+(?P<range_min>-?\d+)\s+and\s+"
    r"(?P<range_max>-?\d+)))\s+"
    r"with\s+(?P<steps>\d+)\s+steps?\s+"
    r"allowing\s+for\s+backlash\s+up\s+to\s+"
    r"(?P<backlash>\d+)",
    re.IGNORECASE,
)

FOCUS_MEASUREMENT_PATTERN = re.compile(
    r"\bFocus\s+measurement\s+of\s+"
    r"(?P<score>[\d.,]+)\s+at\s+"
    r"(?P<position>-?\d+)"
    r".*?\bwhile\s+running\s+step\s+"
    r"(?P<description>Autofocus\b.*?)"
    r"(?:\s+in\s+|\s*$)",
    re.IGNORECASE,
)

BEST_FIT_PATTERN = re.compile(
    r"\bCurrent\s+best\s+fit\s+is\s+"
    r"(?P<status>\w+)\s+with\s+best\s+at\s+"
    r"(?P<position>[\d.,]+),\s+confidence\s+"
    r"(?P<confidence>[\d.,]+),\s+based\s+on\s+"
    r"(?P<points>\d+)\s+points\b",
    re.IGNORECASE,
)

FOCUS_SCAN_RESULT_PATTERN = re.compile(
    r"\bAfter\s+focus\s+scan,\s*best\s+fit\s+gives\s+"
    r"focus\s+score\s+of\s+(?P<score>[\d.,]+)\s+at\s+"
    r"(?P<position>-?\d+)\s+with\s+graph\s+explaining\s+"
    r"(?P<variance>[\d.,]+)\s*(?:%|percent)?\s+"
    r"of\s+variance\b",
    re.IGNORECASE,
)

AUTOFOCUS_RESULT_PATTERN = re.compile(
    r"\bAutofocus\s+result\s*:?\s*best\s+focus\s+at\s+"
    r"(?P<position>[\d.,]+)\s+with\s+focuser\s+temperature\s+of\s+"
    r"(?P<temperature>[-\d.,]+)\s*C\b",
    re.IGNORECASE,
)

AUTOFOCUS_FAILURE_PATTERN = re.compile(
    r"\bAutofocus\s+failed\s*:?\s*(?P<reason>.+?)"
    r"(?:\s+in\s+|\s*$)",
    re.IGNORECASE,
)

OVERSHOOT_START_PATTERN = re.compile(
    r"\bFocuser\s+overshoot\s+handling\s*-\s*"
    r"moving\s+from\s+(?P<from>-?\d+)\s+to\s+"
    r"(?P<to>-?\d+)\s+via\s+(?P<via>-?\d+)\s+"
    r"to\s+allow\s+for\s+overshoot\s+of\s+"
    r"(?P<overshoot>\d+)\b",
    re.IGNORECASE,
)

OVERSHOOT_FINISH_PATTERN = re.compile(
    r"\bFocuser\s+overshoot\s+handling\s*-\s*"
    r"moving\s+from\s+(?P<from>-?\d+)\s+to\s+"
    r"final\s+position\s+of\s+(?P<to>-?\d+)\b",
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
    r"\bRun\s+"
    r"(?P<command>C[-_]?focus[-_]?sequencerfocus(?:[-_]?guide)?\.bat)"
    r"(?:\s+with\s+parameters\s*(?P<parameters>.*?))?"
    r"\s+and\s+wait\s+for\s+it\s+to\s+exit\b",
    re.IGNORECASE,
)

MERIDIAN_LIMIT_PATTERN = re.compile(
    r"\bStop\s+running\s+these\s+steps\s+when\s+"
    r"(?P<degrees>[\d.,]+)\s+degrees\s+from\s+the\s+meridian\b",
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
    r"\bmount\s+is\s+(?:still\s+)?approaching\s+the\s+meridian,"
    r"\s+waiting\s+(?P<minutes>[\d.,]+)\s+minutes\b",
    re.IGNORECASE,
)

SAVED_COORDINATES_PATTERN = re.compile(
    r"\bSaving\s+mount\s+co-ordinates\s+of\s+"
    r"RA(?P<ra>[^,]+),\s*Dec(?P<dec>[^\s]+)\b",
    re.IGNORECASE,
)

MERIDIAN_CAPTURE_CANCEL_PATTERN = re.compile(
    r"\bMount\s+at\s+hour\s+angle\s+of\s+"
    r"(?P<hour_angle>[^,]+),\s*which\s+is\s+within\s+"
    r"(?P<degrees>[\d.,]+)\s+degrees\s+of\s+the\s+meridian\b",
    re.IGNORECASE,
)

NON_ASTRONOMICAL_TARGETS = {
    "",
    "capture",
    "preview",
    "none",
    "light",
    "dark",
    "flat",
    "bias",
}


def read_properties(path: Path) -> dict[str, str]:
    """Read local key=value configuration."""
    if not path.exists():
        example = path.with_name(f"{path.name}.example")
        raise FileNotFoundError(
            f"Configuration file not found: {path}. "
            f"Copy {example.name} to {path.name} first."
        )

    values: dict[str, str] = {}

    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()

        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    return values


def find_latest_log(log_directory: Path) -> Path:
    """Find newest SharpCap Log_*.log recursively."""
    if not log_directory.exists():
        raise FileNotFoundError(
            f"SharpCap log directory does not exist: {log_directory}"
        )

    if not log_directory.is_dir():
        raise NotADirectoryError(
            f"Configured path is not a directory: {log_directory}"
        )

    logs = [
        path
        for path in log_directory.rglob("Log_*.log")
        if path.is_file()
    ]

    if not logs:
        raise FileNotFoundError(
            f"No Log_*.log files found under: {log_directory}"
        )

    return max(logs, key=lambda path: path.stat().st_mtime)


def read_log_lines(log_file: Path) -> list[str]:
    """Read SharpCap log tolerantly."""
    return log_file.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()


def parse_filename_datetime(log_file: Path) -> datetime:
    """Parse session start from the native log filename."""
    match = LOG_FILENAME_PATTERN.match(log_file.name)

    if match is None:
        raise ValueError(
            f"Unsupported SharpCap log filename: {log_file.name}"
        )

    value = (
        f"{match.group('date')} "
        f"{match.group('hour')}:"
        f"{match.group('minute')}:"
        f"{match.group('second')}"
    )

    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def parse_record(
    line: str,
) -> tuple[str, str | None, str | None, str]:
    """Parse a padded, tab-delimited SharpCap record."""
    text = line.lstrip("\ufeff").rstrip()
    match = RECORD_PATTERN.match(text)

    if match is None:
        return "info", None, None, text.strip()

    return (
        match.group("level").lower(),
        match.group("clock"),
        match.group("thread"),
        match.group("message").strip(),
    )


def parse_timestamp(
    session_start: datetime,
    clock_time: str,
    previous_timestamp: datetime | None,
) -> datetime:
    """Combine filename date and record time, handling midnight."""
    event_time = datetime.strptime(
        clock_time,
        "%H:%M:%S.%f",
    ).time()

    if previous_timestamp is None:
        return datetime.combine(session_start.date(), event_time)

    timestamp = datetime.combine(previous_timestamp.date(), event_time)

    if timestamp < previous_timestamp:
        backwards_seconds = (previous_timestamp - timestamp).total_seconds()

        if backwards_seconds > 12 * 60 * 60:
            timestamp += timedelta(days=1)

    return timestamp


def to_number(value: str) -> float:
    """Convert SharpCap decimal text to float."""
    return float(value.replace(",", "."))


def to_iso(value: datetime | None) -> str | None:
    """Convert optional datetime to ISO 8601."""
    return value.isoformat() if value is not None else None


def elapsed_seconds(
    started_at: datetime | None,
    finished_at: datetime | None,
) -> float | None:
    """Return interval in seconds."""
    if started_at is None or finished_at is None:
        return None

    return (finished_at - started_at).total_seconds()


def elapsed_text(seconds: float | None) -> str:
    """Format seconds as HH:MM:SS."""
    if seconds is None:
        return ""

    total = max(0, int(seconds))
    hours, remaining = divmod(total, 3600)
    minutes, secs = divmod(remaining, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def add_unique(values: list[Any], value: Any) -> None:
    """Append only meaningful unique values."""
    if value is not None and value != "" and value not in values:
        values.append(value)


def clean_target(value: str) -> str | None:
    """Remove generic target labels such as Capture."""
    target = value.strip().strip("'").strip('"').strip()

    if target.lower() in NON_ASTRONOMICAL_TARGETS:
        return None

    return target or None


def thermal_bucket_key(value: str) -> str:
    """Map thermal command/script to main or guide telescope."""
    normalized = value.lower().replace("-", "_")

    if "guide" in normalized:
        return "guide_telescope"

    return "main_telescope"


def parse_autofocus_description(description: str) -> dict[str, Any]:
    """Extract autofocus parameters from a textual sequence step."""
    details: dict[str, Any] = {
        "description": description,
        "mode": None,
        "offset_min": None,
        "offset_max": None,
        "range_start": None,
        "range_end": None,
        "configured_steps": None,
        "backlash_steps": None,
    }

    match = AUTOFOCUS_DESCRIPTION_PATTERN.search(description)

    if match is None:
        return details

    details["configured_steps"] = int(match.group("steps"))
    details["backlash_steps"] = int(match.group("backlash"))

    if match.group("offset_min") is not None:
        details["mode"] = "offset"
        details["offset_min"] = int(match.group("offset_min"))
        details["offset_max"] = int(match.group("offset_max"))
    else:
        details["mode"] = "range"
        details["range_start"] = int(match.group("range_min"))
        details["range_end"] = int(match.group("range_max"))

    return details


def new_autofocus_run(
    timestamp: datetime,
    description: str,
    filter_name: str | None,
    exposure_seconds: float | None,
) -> dict[str, Any]:
    """Create autofocus run record."""
    return {
        "started_at": to_iso(timestamp),
        "completed_at": None,
        "duration_seconds": None,
        "duration": "",
        "status": "running",
        "filter": filter_name,
        "exposure_seconds": exposure_seconds,
        **parse_autofocus_description(description),
        "measurements": [],
        "best_fit": None,
        "scan_result": None,
        "result": None,
        "failure_reason": None,
        "moves": [],
    }


def complete_autofocus_run(
    run: dict[str, Any],
    timestamp: datetime,
    status: str | None = None,
) -> None:
    """Close autofocus run."""
    run["completed_at"] = to_iso(timestamp)

    if status is not None:
        run["status"] = status
    elif run["status"] == "running":
        run["status"] = "success" if run["result"] else "completed_without_result"

    started_at = datetime.fromisoformat(run["started_at"])
    seconds = elapsed_seconds(started_at, timestamp)
    run["duration_seconds"] = seconds
    run["duration"] = elapsed_text(seconds)


def new_dither_run(timestamp: datetime) -> dict[str, Any]:
    """Create a dither timing record."""
    return {
        "started_at": to_iso(timestamp),
        "settled_at": None,
        "completed_at": None,
        "duration_seconds": None,
        "duration": "",
        "status": "running",
        "pixels": None,
        "ra_only": None,
        "settle_pixels": None,
        "settle_min_seconds": None,
        "settle_max_seconds": None,
    }


def complete_dither_run(
    run: dict[str, Any],
    timestamp: datetime,
    status: str = "completed",
) -> None:
    """Close dither timing record."""
    run["completed_at"] = to_iso(timestamp)
    run["status"] = status

    started_at = datetime.fromisoformat(run["started_at"])
    seconds = elapsed_seconds(started_at, timestamp)
    run["duration_seconds"] = seconds
    run["duration"] = elapsed_text(seconds)


def new_thermal_execution(
    timestamp: datetime,
    script: str,
) -> dict[str, Any]:
    """Create thermal script execution."""
    return {
        "script": script,
        "command": None,
        "parameters": None,
        "started_at": to_iso(timestamp),
        "finished_at": None,
        "duration_seconds": None,
        "duration": "",
        "status": "running",
    }


def complete_thermal_execution(
    execution: dict[str, Any],
    timestamp: datetime,
) -> None:
    """Close thermal execution."""
    execution["finished_at"] = to_iso(timestamp)
    execution["status"] = "completed"

    started_at = datetime.fromisoformat(execution["started_at"])
    seconds = elapsed_seconds(started_at, timestamp)
    execution["duration_seconds"] = seconds
    execution["duration"] = elapsed_text(seconds)


def create_report_skeleton(
    log_file: Path,
    filename_start: datetime,
) -> dict[str, Any]:
    """Build empty report structure."""
    return {
        "generated_at": datetime.now().astimezone().isoformat(),
        "source_log": {
            "path": str(log_file.resolve()),
            "name": log_file.name,
            "size_bytes": log_file.stat().st_size,
            "filename_session_start": to_iso(filename_start),
            "encoding": "utf-8",
        },
        "session": {},
        "capture": {
            "targets": [],
            "cameras": [],
            "filters": [],
            "frame_types": [],
            "resolutions": [],
            "bayer_patterns": [],
            "science_filters": [],
            "science_exposure_seconds": [],
            "science_frames": [],
            "auxiliary_filters": [],
            "auxiliary_exposure_seconds": [],
            "auxiliary_frames": [],
            "captured_files": [],
            "science_capture_count": 0,
        },
        "sequence": {
            "latest_completed_frames": None,
            "planned_frames": None,
            "guiding_required": None,
            "progress_updates": [],
        },
        "guiding": {
            "dither_runs": [],
            "dither_request_count": 0,
            "dither_total_seconds": 0.0,
            "dither_total_duration": "",
            "dither_average_seconds": None,
            "dither_average_duration": "",
            "settling_count": 0,
            "settled_count": 0,
            "settle_failed_count": 0,
        },
        "focus": {
            "autofocus_runs": [],
            "autofocus_total_seconds": 0.0,
            "autofocus_total_duration": "",
            "autofocus_average_seconds": None,
            "autofocus_average_duration": "",
        },
        "thermal_corrections": {
            "main_telescope": {
                "script": "runfocus.bat",
                "command": "C-focus-sequencerfocus.bat",
                "executions": [],
            },
            "guide_telescope": {
                "script": "runfocusguide.bat",
                "command": "C-focus-sequencerfocusguide.bat",
                "executions": [],
            },
        },
        "meridian_flip": {
            "configured": False,
            "configured_stop_distance_degrees": None,
            "executed": False,
            "started_at": None,
            "completed_at": None,
            "duration_seconds": None,
            "duration": "",
            "capture_cancelled_for_meridian": False,
            "hour_angle_at_cancellation": None,
            "saved_mount_coordinates": None,
            "waiting_detected": False,
            "first_wait_minutes": None,
            "last_wait_minutes": None,
            "guiding_stopped": False,
            "guiding_restarted": False,
            "plate_solves_after_flip": 0,
            "operations": [],
        },
        "diagnostics": {
            "warning_count": 0,
            "error_count": 0,
            "fatal_count": 0,
            "entries": [],
        },
    }


def build_report(log_file: Path) -> dict[str, Any]:
    """Parse a native SharpCap session log."""
    filename_start = parse_filename_datetime(log_file)
    lines = read_log_lines(log_file)

    if not any(
        parse_record(line)[1] is not None
        for line in lines[:500]
    ):
        raise ValueError(
            "The selected file does not contain recognizable SharpCap records."
        )

    report = create_report_skeleton(log_file, filename_start)
    previous_timestamp: datetime | None = None
    timestamps: list[datetime] = []
    current_autofocus: dict[str, Any] | None = None
    current_dither: dict[str, Any] | None = None
    current_thermal: dict[str, dict[str, Any] | None] = {
        "main_telescope": None,
        "guide_telescope": None,
    }

    state: dict[str, Any] = {
        "frame_type": None,
        "filter": None,
        "configured_exposure_seconds": None,
        "capture_block_active": False,
        "capture_block_planned_frames": None,
        "focus_mode_depth": 0,
        "autofocus_active": False,
        "last_exposure_is_science": False,
    }

    parsed_records = 0

    for line_number, line in enumerate(lines, start=1):
        level, clock, thread_id, message = parse_record(line)

        if clock is None:
            continue

        timestamp = parse_timestamp(
            filename_start,
            clock,
            previous_timestamp,
        )
        previous_timestamp = timestamp
        timestamps.append(timestamp)
        parsed_records += 1

        if level == "warning":
            report["diagnostics"]["warning_count"] += 1
        elif level == "error":
            report["diagnostics"]["error_count"] += 1
        elif level == "fatal":
            report["diagnostics"]["fatal_count"] += 1

        if level in {"warning", "error", "fatal"}:
            report["diagnostics"]["entries"].append(
                {
                    "line_number": line_number,
                    "timestamp": to_iso(timestamp),
                    "level": level,
                    "thread_id": thread_id,
                    "message": message,
                }
            )

        meridian = report["meridian_flip"]

        meridian_limit_match = MERIDIAN_LIMIT_PATTERN.search(message)

        if meridian_limit_match:
            meridian["configured"] = True
            meridian["configured_stop_distance_degrees"] = to_number(
                meridian_limit_match.group("degrees")
            )

        meridian_cancel_match = MERIDIAN_CAPTURE_CANCEL_PATTERN.search(
            message
        )

        if meridian_cancel_match:
            meridian["capture_cancelled_for_meridian"] = True
            meridian["hour_angle_at_cancellation"] = (
                meridian_cancel_match.group("hour_angle").strip()
            )
            meridian["operations"].append(
                {
                    "timestamp": to_iso(timestamp),
                    "event": "capture_cancelled_at_meridian_limit",
                    "hour_angle": meridian[
                        "hour_angle_at_cancellation"
                    ],
                }
            )

        saved_coordinates_match = SAVED_COORDINATES_PATTERN.search(message)

        if saved_coordinates_match:
            meridian["saved_mount_coordinates"] = {
                "timestamp": to_iso(timestamp),
                "ra": saved_coordinates_match.group("ra").strip(),
                "dec": saved_coordinates_match.group("dec").strip(),
            }

        if MERIDIAN_FLIP_START_PATTERN.search(message):
            meridian["executed"] = True
            meridian["started_at"] = to_iso(timestamp)
            meridian["operations"].append(
                {
                    "timestamp": to_iso(timestamp),
                    "event": "meridian_flip_started",
                }
            )

        meridian_wait_match = MERIDIAN_WAIT_PATTERN.search(message)

        if meridian_wait_match and meridian["started_at"] is not None:
            wait_minutes = to_number(meridian_wait_match.group("minutes"))
            meridian["waiting_detected"] = True

            if meridian["first_wait_minutes"] is None:
                meridian["first_wait_minutes"] = wait_minutes

            meridian["last_wait_minutes"] = wait_minutes

        if (
            meridian["started_at"] is not None
            and "Guiding GuideState changed to Stopped" in message
        ):
            meridian["guiding_stopped"] = True

        if (
            meridian["started_at"] is not None
            and "Guiding GuideState changed to Guiding" in message
        ):
            meridian["guiding_restarted"] = True

        if (
            meridian["started_at"] is not None
            and "Plate solve succeeded" in message
        ):
            meridian["plate_solves_after_flip"] += 1

        if MERIDIAN_FLIP_COMPLETE_PATTERN.search(message):
            meridian["executed"] = True
            meridian["completed_at"] = to_iso(timestamp)

            started_at = datetime.fromisoformat(meridian["started_at"])
            flip_seconds = elapsed_seconds(started_at, timestamp)
            meridian["duration_seconds"] = flip_seconds
            meridian["duration"] = elapsed_text(flip_seconds)
            meridian["operations"].append(
                {
                    "timestamp": to_iso(timestamp),
                    "event": "meridian_flip_completed",
                }
            )

        frame_type_match = FRAME_TYPE_PATTERN.search(message)

        if frame_type_match:
            state["frame_type"] = (
                frame_type_match.group("frame_type").lower()
            )

        filter_match = FILTER_POSITION_PATTERN.search(message)

        if filter_match and re.search(
            r"\bSequencer\s+(?::\s*)?Completed\s+(?::\s*)?"
            r"Move\s+filter\s+wheel\s+to\s+position\b",
            message,
            re.IGNORECASE,
        ):
            state["filter"] = filter_match.group("filter").strip()

        capture_start_match = CAPTURE_SEQUENCE_START_PATTERN.search(message)

        if capture_start_match:
            state["capture_block_active"] = True
            state["capture_block_planned_frames"] = int(
                capture_start_match.group("count")
            )

        capture_end_match = CAPTURE_SEQUENCE_END_PATTERN.search(message)

        if capture_end_match:
            state["capture_block_active"] = False
            state["capture_block_planned_frames"] = None

        if FOCUS_MODE_START_PATTERN.search(message):
            state["focus_mode_depth"] += 1

        if FOCUS_MODE_END_PATTERN.search(message):
            state["focus_mode_depth"] = max(
                0,
                state["focus_mode_depth"] - 1,
            )

        autofocus_start_match = AUTOFOCUS_STEP_START_PATTERN.search(message)

        if autofocus_start_match:
            state["autofocus_active"] = True

            if current_autofocus is None:
                current_autofocus = new_autofocus_run(
                    timestamp,
                    autofocus_start_match.group("description").strip(),
                    state["filter"],
                    state["configured_exposure_seconds"],
                )
                report["focus"]["autofocus_runs"].append(
                    current_autofocus
                )

        if AUTOFOCUS_STEP_END_PATTERN.search(message):
            state["autofocus_active"] = False

            if (
                current_autofocus is not None
                and current_autofocus["completed_at"] is None
            ):
                complete_autofocus_run(current_autofocus, timestamp)
                current_autofocus = None

        target_match = TARGET_PATTERN.search(message)

        if target_match:
            target = clean_target(target_match.group("target"))
            camera = target_match.group("camera").strip()
            filter_name = target_match.group("filter").strip()
            frame_type = target_match.group("frame_type").strip()

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
            add_unique(
                report["capture"]["resolutions"],
                f"{fits_match.group('width')}x{fits_match.group('height')}",
            )
            add_unique(
                report["capture"]["bayer_patterns"],
                fits_match.group("bayer").strip(),
            )
            add_unique(
                report["capture"]["cameras"],
                fits_match.group("camera").strip(),
            )

        exposure_start_match = EXPOSURE_START_PATTERN.search(message)

        if exposure_start_match:
            exposure_seconds = (
                int(exposure_start_match.group("milliseconds")) / 1000
            )
            state["configured_exposure_seconds"] = exposure_seconds

            is_science_light = (
                state["capture_block_active"]
                and state["frame_type"] == "light"
                and state["focus_mode_depth"] == 0
                and not state["autofocus_active"]
                and (state["filter"] or "").strip().lower() != "none"
            )

            event = {
                "timestamp": to_iso(timestamp),
                "filter": state["filter"],
                "frame_type": state["frame_type"],
                "exposure_seconds": exposure_seconds,
            }

            state["last_exposure_is_science"] = is_science_light

            if is_science_light:
                report["capture"]["science_frames"].append(event)
                add_unique(
                    report["capture"]["science_exposure_seconds"],
                    exposure_seconds,
                )
                add_unique(
                    report["capture"]["science_filters"],
                    state["filter"],
                )
            else:
                report["capture"]["auxiliary_frames"].append(event)
                add_unique(
                    report["capture"]["auxiliary_exposure_seconds"],
                    exposure_seconds,
                )
                add_unique(
                    report["capture"]["auxiliary_filters"],
                    state["filter"],
                )

        exposure_end_match = EXPOSURE_END_PATTERN.search(message)

        if exposure_end_match:
            succeeded = (
                exposure_end_match.group("success").lower() == "true"
            )

            if state["last_exposure_is_science"] and succeeded:
                report["capture"]["science_capture_count"] += 1

        captured_match = CAPTURED_FILE_PATTERN.search(message)

        if captured_match and state["last_exposure_is_science"]:
            report["capture"]["captured_files"].append(
                captured_match.group("path").strip()
            )

        progress_match = PROGRESS_PATTERN.search(message)

        if progress_match:
            completed = int(progress_match.group("completed"))
            total = int(progress_match.group("total"))
            planned = int(progress_match.group("planned"))
            guiding_required = (
                progress_match.group("guiding").lower() == "true"
            )

            report["sequence"]["latest_completed_frames"] = completed
            report["sequence"]["planned_frames"] = planned
            report["sequence"]["guiding_required"] = guiding_required
            report["sequence"]["progress_updates"].append(
                {
                    "timestamp": to_iso(timestamp),
                    "completed": completed,
                    "total": total,
                    "planned": planned,
                    "guiding_required": guiding_required,
                }
            )

        dither_start_match = DITHER_STEP_START_PATTERN.search(message)

        if dither_start_match:
            if current_dither is not None:
                complete_dither_run(
                    current_dither,
                    timestamp,
                    status="interrupted",
                )

            current_dither = new_dither_run(timestamp)
            report["guiding"]["dither_runs"].append(current_dither)

        dither_match = DITHER_PATTERN.search(message)

        if dither_match:
            if current_dither is None:
                current_dither = new_dither_run(timestamp)
                report["guiding"]["dither_runs"].append(current_dither)

            current_dither["pixels"] = to_number(
                dither_match.group("pixels")
            )
            current_dither["ra_only"] = (
                dither_match.group("ra_only").lower() == "true"
            )
            current_dither["settle_pixels"] = to_number(
                dither_match.group("settle_pixels")
            )
            current_dither["settle_min_seconds"] = to_number(
                dither_match.group("settle_min")
            )
            current_dither["settle_max_seconds"] = to_number(
                dither_match.group("settle_max")
            )

        if "Guiding SettleState changed to Settling" in message:
            report["guiding"]["settling_count"] += 1

        if "Guiding SettleState changed to Settled" in message:
            report["guiding"]["settled_count"] += 1

            if current_dither is not None:
                current_dither["settled_at"] = to_iso(timestamp)

        if "SettleFailed" in message:
            report["guiding"]["settle_failed_count"] += 1

        if DITHER_STEP_END_PATTERN.search(message):
            if current_dither is not None:
                complete_dither_run(current_dither, timestamp)
                current_dither = None

        measurement_match = FOCUS_MEASUREMENT_PATTERN.search(message)

        if measurement_match:
            description = measurement_match.group("description").strip()

            if (
                current_autofocus is None
                or current_autofocus["description"] != description
            ):
                if current_autofocus is not None:
                    complete_autofocus_run(
                        current_autofocus,
                        timestamp,
                        status="interrupted",
                    )

                current_autofocus = new_autofocus_run(
                    timestamp,
                    description,
                    state["filter"],
                    state["configured_exposure_seconds"],
                )
                report["focus"]["autofocus_runs"].append(
                    current_autofocus
                )

            current_autofocus["measurements"].append(
                {
                    "timestamp": to_iso(timestamp),
                    "score": to_number(measurement_match.group("score")),
                    "position": int(measurement_match.group("position")),
                }
            )

        best_fit_match = BEST_FIT_PATTERN.search(message)

        if best_fit_match and current_autofocus is not None:
            current_autofocus["best_fit"] = {
                "status": best_fit_match.group("status"),
                "position": to_number(best_fit_match.group("position")),
                "confidence": to_number(
                    best_fit_match.group("confidence")
                ),
                "points": int(best_fit_match.group("points")),
            }

        scan_result_match = FOCUS_SCAN_RESULT_PATTERN.search(message)

        if scan_result_match and current_autofocus is not None:
            current_autofocus["scan_result"] = {
                "score": to_number(scan_result_match.group("score")),
                "position": int(scan_result_match.group("position")),
                "variance_percent": to_number(
                    scan_result_match.group("variance")
                ),
            }

        autofocus_result_match = AUTOFOCUS_RESULT_PATTERN.search(message)

        if autofocus_result_match:
            if current_autofocus is None:
                current_autofocus = new_autofocus_run(
                    timestamp,
                    "Autofocus result without captured measurements",
                    state["filter"],
                    state["configured_exposure_seconds"],
                )
                report["focus"]["autofocus_runs"].append(
                    current_autofocus
                )

            current_autofocus["result"] = {
                "timestamp": to_iso(timestamp),
                "best_focus_position": to_number(
                    autofocus_result_match.group("position")
                ),
                "focuser_temperature_celsius": to_number(
                    autofocus_result_match.group("temperature")
                ),
            }
            complete_autofocus_run(current_autofocus, timestamp)
            current_autofocus = None
            state["autofocus_active"] = False

        autofocus_failure_match = AUTOFOCUS_FAILURE_PATTERN.search(message)

        if autofocus_failure_match and current_autofocus is not None:
            current_autofocus["failure_reason"] = (
                autofocus_failure_match.group("reason").strip()
            )
            complete_autofocus_run(
                current_autofocus,
                timestamp,
                status="failed",
            )
            current_autofocus = None
            state["autofocus_active"] = False

        overshoot_start_match = OVERSHOOT_START_PATTERN.search(message)

        if overshoot_start_match and current_autofocus is not None:
            current_autofocus["moves"].append(
                {
                    "timestamp": to_iso(timestamp),
                    "type": "overshoot_start",
                    "from_position": int(
                        overshoot_start_match.group("from")
                    ),
                    "target_position": int(
                        overshoot_start_match.group("to")
                    ),
                    "via_position": int(
                        overshoot_start_match.group("via")
                    ),
                    "overshoot_steps": int(
                        overshoot_start_match.group("overshoot")
                    ),
                }
            )

        overshoot_finish_match = OVERSHOOT_FINISH_PATTERN.search(message)

        if overshoot_finish_match and current_autofocus is not None:
            current_autofocus["moves"].append(
                {
                    "timestamp": to_iso(timestamp),
                    "type": "overshoot_finish",
                    "from_position": int(
                        overshoot_finish_match.group("from")
                    ),
                    "target_position": int(
                        overshoot_finish_match.group("to")
                    ),
                }
            )

        thermal_start_match = THERMAL_START_PATTERN.search(message)

        if thermal_start_match:
            script = thermal_start_match.group("script")
            key = thermal_bucket_key(script)

            if current_thermal[key] is None:
                execution = new_thermal_execution(timestamp, script)
                report["thermal_corrections"][key]["executions"].append(
                    execution
                )
                current_thermal[key] = execution

        thermal_command_match = THERMAL_COMMAND_PATTERN.search(message)

        if thermal_command_match:
            command = thermal_command_match.group("command")
            key = thermal_bucket_key(command)
            execution = current_thermal[key]

            if execution is None:
                script = (
                    "runfocusguide.bat"
                    if key == "guide_telescope"
                    else "runfocus.bat"
                )
                execution = new_thermal_execution(timestamp, script)
                report["thermal_corrections"][key]["executions"].append(
                    execution
                )
                current_thermal[key] = execution

            execution["command"] = command
            parameters = thermal_command_match.group("parameters")

            if parameters is not None:
                execution["parameters"] = parameters.strip() or None

        thermal_finish_match = THERMAL_FINISH_PATTERN.search(message)

        if thermal_finish_match:
            script = thermal_finish_match.group("script")
            key = thermal_bucket_key(script)
            execution = current_thermal[key]

            if execution is not None:
                complete_thermal_execution(execution, timestamp)
                current_thermal[key] = None

    if parsed_records == 0:
        raise ValueError("No valid SharpCap records were parsed.")

    if current_autofocus is not None:
        complete_autofocus_run(
            current_autofocus,
            timestamps[-1],
            status="unfinished",
        )

    if current_dither is not None:
        complete_dither_run(
            current_dither,
            timestamps[-1],
            status="unfinished",
        )

    for execution in current_thermal.values():
        if execution is not None:
            execution["status"] = "unfinished"

    session_start = min(timestamps)
    session_end = max(timestamps)
    session_duration = elapsed_seconds(session_start, session_end)

    report["session"] = {
        "start": to_iso(session_start),
        "end": to_iso(session_end),
        "duration_seconds": session_duration,
        "duration": elapsed_text(session_duration),
        "parsed_record_count": parsed_records,
    }

    report["capture"]["captured_file_count"] = len(
        report["capture"]["captured_files"]
    )
    report["capture"]["captured_files"] = report["capture"][
        "captured_files"
    ][-100:]
    report["capture"]["science_frame_event_count"] = len(
        report["capture"]["science_frames"]
    )
    report["capture"]["auxiliary_frame_event_count"] = len(
        report["capture"]["auxiliary_frames"]
    )

    report["sequence"]["progress_update_count"] = len(
        report["sequence"]["progress_updates"]
    )
    report["sequence"]["progress_updates"] = report["sequence"][
        "progress_updates"
    ][-100:]

    dither_durations = [
        run["duration_seconds"]
        for run in report["guiding"]["dither_runs"]
        if run.get("duration_seconds") is not None
    ]
    dither_total = sum(dither_durations)
    dither_average = (
        dither_total / len(dither_durations)
        if dither_durations
        else None
    )

    report["guiding"]["dither_request_count"] = len(
        report["guiding"]["dither_runs"]
    )
    report["guiding"]["dither_total_seconds"] = dither_total
    report["guiding"]["dither_total_duration"] = elapsed_text(
        dither_total
    )
    report["guiding"]["dither_average_seconds"] = dither_average
    report["guiding"]["dither_average_duration"] = elapsed_text(
        dither_average
    )

    autofocus_durations = [
        run["duration_seconds"]
        for run in report["focus"]["autofocus_runs"]
        if run.get("duration_seconds") is not None
    ]
    autofocus_total = sum(autofocus_durations)
    autofocus_average = (
        autofocus_total / len(autofocus_durations)
        if autofocus_durations
        else None
    )

    report["focus"]["autofocus_run_count"] = len(
        report["focus"]["autofocus_runs"]
    )
    report["focus"]["autofocus_total_seconds"] = autofocus_total
    report["focus"]["autofocus_total_duration"] = elapsed_text(
        autofocus_total
    )
    report["focus"]["autofocus_average_seconds"] = autofocus_average
    report["focus"]["autofocus_average_duration"] = elapsed_text(
        autofocus_average
    )

    for correction in report["thermal_corrections"].values():
        correction["execution_count"] = len(correction["executions"])

    return report


def build_focus_rows(report: dict[str, Any]) -> list[dict[str, str]]:
    """Build CSV/TXT focus and thermal event rows."""
    rows: list[dict[str, str]] = []

    for run in report["focus"]["autofocus_runs"]:
        result = run.get("result") or {}
        scan = run.get("scan_result") or {}
        measurements = run.get("measurements") or []

        first_position = (
            measurements[0]["position"]
            if measurements
            else ""
        )
        last_position = (
            measurements[-1]["position"]
            if measurements
            else ""
        )

        if run["mode"] == "offset":
            parameters = (
                f"Offset {run['offset_min']}..{run['offset_max']}; "
                f"{run['configured_steps']} steps; "
                f"backlash {run['backlash_steps']}"
            )
        elif run["mode"] == "range":
            parameters = (
                f"Range {run['range_start']}..{run['range_end']}; "
                f"{run['configured_steps']} steps; "
                f"backlash {run['backlash_steps']}"
            )
        else:
            parameters = run["description"]

        rows.append(
            {
                "timestamp": run["started_at"] or "",
                "source": "SharpCap autofocus",
                "status": run["status"] or "",
                "filter": run.get("filter") or "",
                "exposure_seconds": str(
                    run.get("exposure_seconds") or ""
                ),
                "parameters": parameters,
                "start_position": str(first_position),
                "best_position": str(
                    result.get("best_focus_position")
                    or scan.get("position")
                    or ""
                ),
                "final_position": str(last_position),
                "temperature_celsius": str(
                    result.get("focuser_temperature_celsius") or ""
                ),
                "focus_score": str(scan.get("score") or ""),
                "variance_percent": str(
                    scan.get("variance_percent") or ""
                ),
                "duration": run["duration"] or "",
            }
        )

    labels = {
        "main_telescope": "C8 thermal correction",
        "guide_telescope": "ED50 thermal correction",
    }

    for key, label in labels.items():
        correction = report["thermal_corrections"][key]

        for execution in correction["executions"]:
            command = execution["command"] or correction["command"]
            parameters = execution["parameters"] or ""

            rows.append(
                {
                    "timestamp": execution["started_at"] or "",
                    "source": label,
                    "status": execution["status"] or "",
                    "filter": "",
                    "exposure_seconds": "",
                    "parameters": (
                        f"{command} {parameters}".strip()
                    ),
                    "start_position": "",
                    "best_position": "",
                    "final_position": "",
                    "temperature_celsius": "",
                    "focus_score": "",
                    "variance_percent": "",
                    "duration": execution["duration"] or "",
                }
            )

    return sorted(rows, key=lambda row: row["timestamp"])


def write_reports(report: dict[str, Any]) -> tuple[Path, Path, Path]:
    """Write session JSON and focus CSV/TXT reports."""
    REPORTS_DIRECTORY.mkdir(parents=True, exist_ok=True)
    suffix = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = REPORTS_DIRECTORY / (
        f"sharpcap_session_report_{suffix}.json"
    )
    csv_path = REPORTS_DIRECTORY / (
        f"sharpcap_focus_corrections_{suffix}.csv"
    )
    text_path = REPORTS_DIRECTORY / (
        f"sharpcap_focus_corrections_{suffix}.txt"
    )

    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    rows = build_focus_rows(report)
    fields = [
        "timestamp",
        "source",
        "status",
        "filter",
        "exposure_seconds",
        "parameters",
        "start_position",
        "best_position",
        "final_position",
        "temperature_celsius",
        "focus_score",
        "variance_percent",
        "duration",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    headers = [
        "Timestamp",
        "Source",
        "Status",
        "Filter",
        "Exposure s",
        "Parameters",
        "Start",
        "Best",
        "Final",
        "Temp C",
        "Score",
        "Variance %",
        "Duration",
    ]

    text_lines = [
        "SharpCap Focus Corrections",
        "=" * 26,
        "",
        " | ".join(headers),
        "-" * 160,
    ]

    for row in rows:
        text_lines.append(
            " | ".join(
                [
                    row["timestamp"],
                    row["source"],
                    row["status"],
                    row["filter"],
                    row["exposure_seconds"],
                    row["parameters"],
                    row["start_position"],
                    row["best_position"],
                    row["final_position"],
                    row["temperature_celsius"],
                    row["focus_score"],
                    row["variance_percent"],
                    row["duration"],
                ]
            )
        )

    if not rows:
        text_lines.append(
            "No autofocus or thermal correction events found."
        )

    text_path.write_text(
        "\n".join(text_lines) + "\n",
        encoding="utf-8",
    )

    return json_path, csv_path, text_path


def format_values(
    values: list[Any],
    suffix: str = "",
) -> str:
    """Format values for terminal summary."""
    if not values:
        return "Not detected"

    return ", ".join(f"{value}{suffix}" for value in values)


def print_summary(
    report: dict[str, Any],
    json_path: Path,
    csv_path: Path,
    text_path: Path,
) -> None:
    """Print concise but useful session summary."""
    capture = report["capture"]
    sequence = report["sequence"]
    guiding = report["guiding"]
    focus = report["focus"]
    thermal = report["thermal_corrections"]
    meridian = report["meridian_flip"]
    diagnostics = report["diagnostics"]

    print("SharpCap Session Analyzer")
    print("=" * 30)
    print(f"Log file: {report['source_log']['name']}")
    print(f"Session start: {report['session']['start']}")
    print(f"Session end: {report['session']['end']}")
    print(f"Duration: {report['session']['duration']}")
    print(f"Target: {format_values(capture['targets'])}")
    print(f"Camera: {format_values(capture['cameras'])}")
    print(
        "Light frame type(s): "
        f"{format_values(capture['frame_types'])}"
    )
    print(
        "Light filter(s): "
        f"{format_values(capture['science_filters'])}"
    )
    print(
        "Light exposure(s): "
        f"{format_values(capture['science_exposure_seconds'], ' s')}"
    )
    print(
        "Focus/auxiliary filter(s): "
        f"{format_values(capture['auxiliary_filters'])}"
    )
    print(
        "Focus/auxiliary exposure(s): "
        f"{format_values(capture['auxiliary_exposure_seconds'], ' s')}"
    )
    print(
        "Science exposure events: "
        f"{capture['science_frame_event_count']}"
    )
    print(
        "Auxiliary exposure events: "
        f"{capture['auxiliary_frame_event_count']}"
    )
    print(
        "Frames: "
        f"{sequence['latest_completed_frames'] or 0}/"
        f"{sequence['planned_frames'] or 'Not detected'}"
    )
    print(f"Dither requests: {guiding['dither_request_count']}")
    print(
        "Total dither time: "
        f"{guiding['dither_total_duration'] or '00:00:00'}"
    )
    print(
        "Average dither time: "
        f"{guiding['dither_average_duration'] or '00:00:00'}"
    )
    print(f"Autofocus runs: {focus['autofocus_run_count']}")
    print(
        "Total autofocus time: "
        f"{focus['autofocus_total_duration'] or '00:00:00'}"
    )
    print(
        "Average autofocus time: "
        f"{focus['autofocus_average_duration'] or '00:00:00'}"
    )
    print(
        "Main thermal corrections: "
        f"{thermal['main_telescope']['execution_count']}"
    )
    print(
        "Guide thermal corrections: "
        f"{thermal['guide_telescope']['execution_count']}"
    )
    print(
        "Meridian flip configured: "
        f"{'yes' if meridian['configured'] else 'no'}"
    )
    print(
        "Meridian stop limit: "
        f"{meridian['configured_stop_distance_degrees'] or 'Not detected'} degrees"
    )
    print(
        "Meridian flip executed: "
        f"{'yes' if meridian['executed'] else 'no'}"
    )

    if meridian["executed"]:
        print(f"Meridian flip start: {meridian['started_at']}")
        print(f"Meridian flip end: {meridian['completed_at']}")
        print(
            "Meridian flip duration: "
            f"{meridian['duration'] or 'Not detected'}"
        )
        print(
            "Capture cancelled at meridian: "
            f"{'yes' if meridian['capture_cancelled_for_meridian'] else 'no'}"
        )
        print(
            "Saved mount coordinates: "
            f"{meridian['saved_mount_coordinates'] or 'Not detected'}"
        )
        print(
            "Guiding stopped for flip: "
            f"{'yes' if meridian['guiding_stopped'] else 'no'}"
        )
        print(
            "Guiding restarted after flip: "
            f"{'yes' if meridian['guiding_restarted'] else 'no'}"
        )
        print(
            "Post-flip plate solves: "
            f"{meridian['plate_solves_after_flip']}"
        )

    print(f"Warnings: {diagnostics['warning_count']}")
    print(f"Errors: {diagnostics['error_count']}")
    print(f"Fatal records: {diagnostics['fatal_count']}")
    print(f"JSON report: {json_path}")
    print(f"Focus corrections CSV: {csv_path}")
    print(f"Focus corrections table: {text_path}")


def main() -> int:
    """Run analyzer on newest configured SharpCap log."""
    try:
        properties = read_properties(CONFIG_PATH)
        log_directory_value = properties.get("sharpcap.logs.path")

        if not log_directory_value:
            raise KeyError(
                "Missing required property: sharpcap.logs.path"
            )

        log_file = find_latest_log(Path(log_directory_value))
        report = build_report(log_file)
        json_path, csv_path, text_path = write_reports(report)

        print_summary(report, json_path, csv_path, text_path)
        return 0

    except (
        FileNotFoundError,
        NotADirectoryError,
        KeyError,
        OSError,
        UnicodeError,
        ValueError,
    ) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())