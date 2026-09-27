#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 David Gonzalez Lopez-Tercero <davidglt@dragonit.es>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
SharpCap Session Log Analyzer.

Analyze the latest SharpCap log from the directory configured in
sharpcap_sequence_analyzer.properties.

Expected SharpCap record format:
    Info<TAB>21:57:04.149905<TAB>#1<TAB>Starting SharpCap ...

Reports are written to reports/ beside this script:
- sharpcap_session_report_YYYYMMDD_HHMMSS.json
- sharpcap_focus_corrections_YYYYMMDD_HHMMSS.csv
- sharpcap_focus_corrections_YYYYMMDD_HHMMSS.txt
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
    r"(?P<time>\d{2}_\d{2}_\d{2})-\d+\.log$",
    re.IGNORECASE,
)

TIME_PATTERN = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d{1,6}$")

TARGET_PATTERN = re.compile(
    r"Creating file name provider for target "
    r"(?P<target>[^,]+),\s*"
    r"(?P<camera>[^,]+),\s*"
    r"(?P<filter>[^,]+),\s*"
    r"(?P<frame_type>\w+)",
    re.IGNORECASE,
)

FITS_PATTERN = re.compile(
    r"Initializing FitsFileWriter at "
    r"(?P<width>\d+)x(?P<height>\d+)x"
    r"(?P<planes>\d+)x(?P<bits>\d+)bits,\s*"
    r"(?P<bayer>[^,]+),.*?for\s+"
    r"(?P<camera>.+?)\s+in\s+void",
    re.IGNORECASE,
)

EXPOSURE_START_PATTERN = re.compile(
    r"Starting ZWO Exposure of (?P<milliseconds>\d+)ms",
    re.IGNORECASE,
)

EXPOSURE_END_PATTERN = re.compile(
    r"Finished ZWO Exposure of (?P<milliseconds>\d+)ms,\s*"
    r"gotFrame\s+(?P<success>True|False)",
    re.IGNORECASE,
)

CAPTURED_FILE_PATTERN = re.compile(
    r"Captured to (?P<path>.+?\.(?:fits|fit|ser|png|tif|tiff))",
    re.IGNORECASE,
)

PROGRESS_PATTERN = re.compile(
    r"Sequencer Progress completed "
    r"(?P<completed>\d+) of (?P<total>\d+) "
    r"Capture (?P<planned>\d+) still frames "
    r"guiding required (?P<guiding>True|False)",
    re.IGNORECASE,
)

DITHER_PATTERN = re.compile(
    r"Requesting dither from PHD2 "
    r"(?P<pixels>[\d.,]+),\s*"
    r"(?P<ra_only>True|False),\s*"
    r"(?P<settle_pixels>[\d.,]+),\s*"
    r"(?P<settle_min>\d+),\s*"
    r"(?P<settle_max>\d+)",
    re.IGNORECASE,
)

AUTOFOCUS_START_PATTERN = re.compile(
    r"Sequencer Starting "
    r"(?P<description>Autofocus "
    r"(?:from offset -?\d+ to -?\d+|between \d+ and \d+) "
    r"with \d+ steps allowing for backlash up to \d+)",
    re.IGNORECASE,
)

AUTOFOCUS_COMPLETE_PATTERN = re.compile(
    r"Sequencer Completed "
    r"(?P<description>Autofocus "
    r"(?:from offset -?\d+ to -?\d+|between \d+ and \d+) "
    r"with \d+ steps allowing for backlash up to \d+)",
    re.IGNORECASE,
)

AUTOFOCUS_OFFSET_PATTERN = re.compile(
    r"Autofocus from offset "
    r"(?P<minimum>-?\d+) to (?P<maximum>-?\d+) "
    r"with (?P<steps>\d+) steps allowing for backlash up to "
    r"(?P<backlash>\d+)",
    re.IGNORECASE,
)

AUTOFOCUS_RANGE_PATTERN = re.compile(
    r"Autofocus between "
    r"(?P<minimum>\d+) and (?P<maximum>\d+) "
    r"with (?P<steps>\d+) steps allowing for backlash up to "
    r"(?P<backlash>\d+)",
    re.IGNORECASE,
)

FOCUS_MEASUREMENT_PATTERN = re.compile(
    r"Focus measurement of (?P<score>[\d.,]+) at "
    r"(?P<position>\d+) while running step Autofocus",
    re.IGNORECASE,
)

BEST_FIT_PATTERN = re.compile(
    r"Current best fit is (?P<status>\w+) with best at "
    r"(?P<position>[\d.,]+), confidence "
    r"(?P<confidence>[\d.,]+), based on "
    r"(?P<points>\d+) points",
    re.IGNORECASE,
)

FOCUS_SCAN_RESULT_PATTERN = re.compile(
    r"After focus scan, best fit gives focus score of "
    r"(?P<score>[\d.]+) at (?P<position>\d+) "
    r"with graph explaining (?P<variance>[\d.]+) of variance",
    re.IGNORECASE,
)

AUTOFOCUS_RESULT_PATTERN = re.compile(
    r"Autofocus result best focus at "
    r"(?P<position>[\d.]+) with focuser temperature of "
    r"(?P<temperature>[\d.]+) C",
    re.IGNORECASE,
)

AUTOFOCUS_FAILURE_PATTERN = re.compile(
    r"Autofocus failed (?P<reason>.+?) "
    r"while running step",
    re.IGNORECASE,
)

OVERSHOOT_START_PATTERN = re.compile(
    r"Focuser overshoot handling - moving from "
    r"(?P<from>\d+) to (?P<to>\d+) via "
    r"(?P<via>\d+) to allow for overshoot of "
    r"(?P<overshoot>\d+)",
    re.IGNORECASE,
)

OVERSHOOT_FINISH_PATTERN = re.compile(
    r"Focuser overshoot handling - moving from "
    r"(?P<from>\d+) to final position of (?P<to>\d+)",
    re.IGNORECASE,
)

THERMAL_START_PATTERN = re.compile(
    r"Thermal correction starting "
    r"(?P<script>runfocus(?:guide)?\.bat)",
    re.IGNORECASE,
)

THERMAL_FINISH_PATTERN = re.compile(
    r"Thermal correction finished "
    r"(?P<script>runfocus(?:guide)?\.bat)",
    re.IGNORECASE,
)

THERMAL_COMMAND_START_PATTERN = re.compile(
    r"Sequencer Starting Run "
    r"(?P<command>C-focus-sequencerfocus(?:guide)?\.bat)"
    r"(?: with parameters(?P<parameters>.*?))? "
    r"and wait for it to exit",
    re.IGNORECASE,
)

THERMAL_COMMAND_FINISH_PATTERN = re.compile(
    r"Sequencer Completed Run "
    r"(?P<command>C-focus-sequencerfocus(?:guide)?\.bat)"
    r"(?: with parameters(?P<parameters>.*?))? "
    r"and wait for it to exit",
    re.IGNORECASE,
)

MERIDIAN_LIMIT_PATTERN = re.compile(
    r"Sequencer Starting Stop running these steps when "
    r"(?P<degrees>[\d.,]+) degrees from the meridian",
    re.IGNORECASE,
)

MERIDIAN_FLIP_START_PATTERN = re.compile(
    r"Sequencer Starting (?:Mount flip|Flip the mount)",
    re.IGNORECASE,
)

MERIDIAN_FLIP_FINISH_PATTERN = re.compile(
    r"Sequencer Completed (?:Mount flip|Flip the mount)",
    re.IGNORECASE,
)


def read_properties(path: Path) -> dict[str, str]:
    """Read the local Java-style properties file."""
    if not path.exists():
        example_path = path.with_name(f"{path.name}.example")
        raise FileNotFoundError(
            f"Configuration file not found: {path}. "
            f"Copy {example_path.name} to {path.name} first."
        )

    properties: dict[str, str] = {}

    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()

        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue

        key, value = line.split("=", 1)
        properties[key.strip()] = value.strip()

    return properties


def read_log_lines(log_file: Path) -> list[str]:
    """Read the UTF-8 SharpCap log."""
    return log_file.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()


def find_latest_log(log_directory: Path) -> Path:
    """Find the most recently modified SharpCap Log_*.log file."""
    if not log_directory.exists():
        raise FileNotFoundError(
            f"SharpCap log directory does not exist: {log_directory}"
        )

    if not log_directory.is_dir():
        raise NotADirectoryError(
            f"Configured path is not a directory: {log_directory}"
        )

    log_files = [
        path
        for path in log_directory.rglob("Log_*.log")
        if path.is_file()
    ]

    if not log_files:
        raise FileNotFoundError(
            f"No Log_*.log files found under: {log_directory}"
        )

    return max(log_files, key=lambda path: path.stat().st_mtime)


def parse_filename_datetime(log_file: Path) -> datetime:
    """Extract the starting date/time encoded in a log filename."""
    match = LOG_FILENAME_PATTERN.match(log_file.name)

    if not match:
        raise ValueError(
            f"Unsupported SharpCap log filename: {log_file.name}"
        )

    value = (
        f"{match.group('date')} "
        f"{match.group('time').replace('_', ':')}"
    )

    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def parse_record(
    line: str,
) -> tuple[str, str | None, str | None, str]:
    """
    Parse SharpCap's tab-delimited format.

    Expected columns:
        LEVEL<TAB>HH:MM:SS.ffffff<TAB>#THREAD<TAB>MESSAGE
    """
    parts = line.split("\t", maxsplit=3)

    if len(parts) != 4:
        return "info", None, None, line.strip()

    raw_level, raw_time, raw_thread, message = (
        value.strip()
        for value in parts
    )

    level = raw_level.lower()

    if level not in {"trace", "debug", "info", "warning", "error", "fatal"}:
        return "info", None, None, line.strip()

    if not TIME_PATTERN.fullmatch(raw_time):
        return "info", None, None, line.strip()

    thread_match = re.fullmatch(r"#(?P<thread>\d+)", raw_thread)

    if not thread_match:
        return "info", None, None, line.strip()

    return level, raw_time, thread_match.group("thread"), message


def parse_timestamp(
    session_start: datetime,
    clock_time: str,
    previous_timestamp: datetime | None,
) -> datetime:
    """Combine SharpCap time-of-day with the filename date."""
    time_value = datetime.strptime(
        clock_time,
        "%H:%M:%S.%f",
    ).time()

    if previous_timestamp is None:
        return datetime.combine(session_start.date(), time_value)

    timestamp = datetime.combine(previous_timestamp.date(), time_value)

    if timestamp < previous_timestamp:
        backward_seconds = (previous_timestamp - timestamp).total_seconds()

        if backward_seconds > 12 * 60 * 60:
            timestamp += timedelta(days=1)

    return timestamp


def number(value: str) -> float:
    """Convert comma or dot decimal strings to float."""
    return float(value.replace(",", "."))


def iso(value: datetime | None) -> str | None:
    """Return ISO text for an optional datetime."""
    return value.isoformat() if value is not None else None


def duration(
    start: datetime | None,
    end: datetime | None,
) -> float | None:
    """Calculate optional elapsed seconds."""
    if start is None or end is None:
        return None

    return (end - start).total_seconds()


def duration_text(seconds: float | None) -> str:
    """Format optional seconds as HH:MM:SS."""
    if seconds is None:
        return ""

    total = int(seconds)
    hours, remainder = divmod(total, 3_600)
    minutes, seconds = divmod(remainder, 60)

    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def add_unique(values: list[Any], value: Any) -> None:
    """Add an item to a list only once."""
    if value not in values:
        values.append(value)


def new_autofocus_run(
    timestamp: datetime,
    description: str,
) -> dict[str, Any]:
    """Create an autofocus run dictionary."""
    run: dict[str, Any] = {
        "started_at": iso(timestamp),
        "completed_at": None,
        "duration_seconds": None,
        "duration": "",
        "description": description,
        "status": "running",
        "mode": None,
        "offset_min": None,
        "offset_max": None,
        "range_start": None,
        "range_end": None,
        "configured_steps": None,
        "backlash_steps": None,
        "measurements": [],
        "best_fit": None,
        "scan_result": None,
        "result": None,
        "failure_reason": None,
        "moves": [],
    }

    offset_match = AUTOFOCUS_OFFSET_PATTERN.search(description)

    if offset_match:
        run["mode"] = "offset"
        run["offset_min"] = int(offset_match.group("minimum"))
        run["offset_max"] = int(offset_match.group("maximum"))
        run["configured_steps"] = int(offset_match.group("steps"))
        run["backlash_steps"] = int(offset_match.group("backlash"))
        return run

    range_match = AUTOFOCUS_RANGE_PATTERN.search(description)

    if range_match:
        run["mode"] = "range"
        run["range_start"] = int(range_match.group("minimum"))
        run["range_end"] = int(range_match.group("maximum"))
        run["configured_steps"] = int(range_match.group("steps"))
        run["backlash_steps"] = int(range_match.group("backlash"))

    return run


def close_autofocus_run(
    run: dict[str, Any],
    timestamp: datetime,
) -> None:
    """Close autofocus run timing and set its successful state if applicable."""
    run["completed_at"] = iso(timestamp)

    if run["status"] == "running":
        run["status"] = "success" if run["result"] else "completed_without_result"

    start = datetime.fromisoformat(run["started_at"])
    elapsed = duration(start, timestamp)
    run["duration_seconds"] = elapsed
    run["duration"] = duration_text(elapsed)


def thermal_key(script: str) -> str:
    """Map a known thermal script to its telescope identifier."""
    return (
        "guide_telescope"
        if script.lower() == "runfocusguide.bat"
        else "main_telescope"
    )


def build_report(log_file: Path) -> dict[str, Any]:
    """Parse one SharpCap log into a structured session report."""
    session_filename_start = parse_filename_datetime(log_file)
    lines = read_log_lines(log_file)

    if not any(parse_record(line)[1] for line in lines[:100]):
        raise ValueError(
            "The selected log does not use the expected SharpCap "
            "tab-delimited record format."
        )

    report: dict[str, Any] = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "source_log": {
            "path": str(log_file.resolve()),
            "name": log_file.name,
            "size_bytes": log_file.stat().st_size,
            "filename_session_start": iso(session_filename_start),
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
            "science_exposure_seconds": [],
            "auxiliary_exposure_seconds": [],
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
            "dither_requests": [],
            "settling_count": 0,
            "settled_count": 0,
            "settle_failed_count": 0,
        },
        "focus": {
            "autofocus_runs": [],
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
            "operations": [],
        },
        "diagnostics": {
            "warning_count": 0,
            "error_count": 0,
            "fatal_count": 0,
            "entries": [],
        },
    }

    current_autofocus: dict[str, Any] | None = None
    current_thermal: dict[str, dict[str, Any] | None] = {
        "main_telescope": None,
        "guide_telescope": None,
    }
    science_context = False
    previous_timestamp: datetime | None = None
    timestamps: list[datetime] = []
    parsed_records = 0

    for line_number, line in enumerate(lines, start=1):
        level, clock_time, thread_id, message = parse_record(line)

        if clock_time is None:
            continue

        timestamp = parse_timestamp(
            session_filename_start,
            clock_time,
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
                    "timestamp": iso(timestamp),
                    "level": level,
                    "thread_id": thread_id,
                    "message": message,
                }
            )

        target_match = TARGET_PATTERN.search(message)

        if target_match:
            add_unique(
                report["capture"]["targets"],
                target_match.group("target").strip(),
            )
            add_unique(
                report["capture"]["cameras"],
                target_match.group("camera").strip(),
            )
            add_unique(
                report["capture"]["filters"],
                target_match.group("filter").strip(),
            )
            add_unique(
                report["capture"]["frame_types"],
                target_match.group("frame_type").strip(),
            )
            science_context = True

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
            seconds = int(
                exposure_start_match.group("milliseconds")
            ) / 1_000

            if science_context:
                add_unique(
                    report["capture"]["science_exposure_seconds"],
                    seconds,
                )
            else:
                add_unique(
                    report["capture"]["auxiliary_exposure_seconds"],
                    seconds,
                )

        exposure_end_match = EXPOSURE_END_PATTERN.search(message)

        if exposure_end_match and science_context:
            if exposure_end_match.group("success").lower() == "true":
                report["capture"]["science_capture_count"] += 1

        captured_match = CAPTURED_FILE_PATTERN.search(message)

        if captured_match:
            report["capture"]["captured_files"].append(
                captured_match.group("path")
            )
            science_context = False

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
                    "timestamp": iso(timestamp),
                    "completed": completed,
                    "total": total,
                    "planned": planned,
                    "guiding_required": guiding_required,
                }
            )

        dither_match = DITHER_PATTERN.search(message)

        if dither_match:
            report["guiding"]["dither_requests"].append(
                {
                    "timestamp": iso(timestamp),
                    "pixels": number(dither_match.group("pixels")),
                    "ra_only": (
                        dither_match.group("ra_only").lower() == "true"
                    ),
                    "settle_pixels": number(
                        dither_match.group("settle_pixels")
                    ),
                    "settle_min_seconds": int(
                        dither_match.group("settle_min")
                    ),
                    "settle_max_seconds": int(
                        dither_match.group("settle_max")
                    ),
                }
            )

        if re.search(
            r"Guiding SettleState changed to Settling",
            message,
            re.IGNORECASE,
        ):
            report["guiding"]["settling_count"] += 1

        if re.search(
            r"Guiding SettleState changed to Settled",
            message,
            re.IGNORECASE,
        ):
            report["guiding"]["settled_count"] += 1

        if re.search(
            r"Event received from PHD2 SettleFailed",
            message,
            re.IGNORECASE,
        ):
            report["guiding"]["settle_failed_count"] += 1

        autofocus_start_match = AUTOFOCUS_START_PATTERN.search(message)

        if autofocus_start_match:
            if current_autofocus is not None:
                current_autofocus["status"] = "interrupted"
                close_autofocus_run(current_autofocus, timestamp)

            current_autofocus = new_autofocus_run(
                timestamp,
                autofocus_start_match.group("description"),
            )
            report["focus"]["autofocus_runs"].append(current_autofocus)
            continue

        if current_autofocus is not None:
            measurement_match = FOCUS_MEASUREMENT_PATTERN.search(message)

            if measurement_match:
                current_autofocus["measurements"].append(
                    {
                        "timestamp": iso(timestamp),
                        "score": number(measurement_match.group("score")),
                        "position": int(
                            measurement_match.group("position")
                        ),
                    }
                )

            best_fit_match = BEST_FIT_PATTERN.search(message)

            if best_fit_match:
                current_autofocus["best_fit"] = {
                    "status": best_fit_match.group("status"),
                    "position": number(best_fit_match.group("position")),
                    "confidence": number(
                        best_fit_match.group("confidence")
                    ),
                    "points": int(best_fit_match.group("points")),
                }

            scan_result_match = FOCUS_SCAN_RESULT_PATTERN.search(message)

            if scan_result_match:
                current_autofocus["scan_result"] = {
                    "score": float(scan_result_match.group("score")),
                    "position": int(scan_result_match.group("position")),
                    "variance_percent": float(
                        scan_result_match.group("variance")
                    ),
                }

            autofocus_result_match = AUTOFOCUS_RESULT_PATTERN.search(message)

            if autofocus_result_match:
                current_autofocus["result"] = {
                    "timestamp": iso(timestamp),
                    "best_focus_position": float(
                        autofocus_result_match.group("position")
                    ),
                    "focuser_temperature_celsius": float(
                        autofocus_result_match.group("temperature")
                    ),
                }

            autofocus_failure_match = AUTOFOCUS_FAILURE_PATTERN.search(message)

            if autofocus_failure_match:
                current_autofocus["status"] = "failed"
                current_autofocus["failure_reason"] = (
                    autofocus_failure_match.group("reason").strip()
                )

            overshoot_start_match = OVERSHOOT_START_PATTERN.search(message)

            if overshoot_start_match:
                current_autofocus["moves"].append(
                    {
                        "timestamp": iso(timestamp),
                        "type": "overshoot_start",
                        "from_position": int(
                            overshoot_start_match.group("from")
                        ),
                        "via_position": int(
                            overshoot_start_match.group("via")
                        ),
                        "target_position": int(
                            overshoot_start_match.group("to")
                        ),
                        "overshoot_steps": int(
                            overshoot_start_match.group("overshoot")
                        ),
                    }
                )

            overshoot_finish_match = OVERSHOOT_FINISH_PATTERN.search(message)

            if overshoot_finish_match:
                current_autofocus["moves"].append(
                    {
                        "timestamp": iso(timestamp),
                        "type": "overshoot_finish",
                        "from_position": int(
                            overshoot_finish_match.group("from")
                        ),
                        "target_position": int(
                            overshoot_finish_match.group("to")
                        ),
                    }
                )

            if AUTOFOCUS_COMPLETE_PATTERN.search(message):
                close_autofocus_run(current_autofocus, timestamp)
                current_autofocus = None

        thermal_start_match = THERMAL_START_PATTERN.search(message)

        if thermal_start_match:
            script = thermal_start_match.group("script")
            key = thermal_key(script)

            execution = {
                "script": script,
                "command": None,
                "parameters": None,
                "started_at": iso(timestamp),
                "finished_at": None,
                "duration_seconds": None,
                "duration": "",
                "status": "running",
            }

            report["thermal_corrections"][key]["executions"].append(execution)
            current_thermal[key] = execution

        command_start_match = THERMAL_COMMAND_START_PATTERN.search(message)

        if command_start_match:
            command = command_start_match.group("command")
            key = (
                "guide_telescope"
                if "guide" in command.lower()
                else "main_telescope"
            )
            execution = current_thermal[key]

            if execution is not None:
                execution["command"] = command
                execution["parameters"] = (
                    command_start_match.group("parameters").strip()
                    or None
                )

        thermal_finish_match = THERMAL_FINISH_PATTERN.search(message)

        if thermal_finish_match:
            script = thermal_finish_match.group("script")
            key = thermal_key(script)
            execution = current_thermal[key]

            if execution is not None:
                execution["finished_at"] = iso(timestamp)
                execution["status"] = "completed"

                started = datetime.fromisoformat(execution["started_at"])
                elapsed = duration(started, timestamp)
                execution["duration_seconds"] = elapsed
                execution["duration"] = duration_text(elapsed)
                current_thermal[key] = None

        meridian_limit_match = MERIDIAN_LIMIT_PATTERN.search(message)

        if meridian_limit_match:
            report["meridian_flip"]["configured"] = True
            report["meridian_flip"][
                "configured_stop_distance_degrees"
            ] = number(meridian_limit_match.group("degrees"))
            report["meridian_flip"]["operations"].append(
                {
                    "timestamp": iso(timestamp),
                    "operation": "meridian_stop_limit",
                }
            )

        if MERIDIAN_FLIP_START_PATTERN.search(message):
            report["meridian_flip"]["executed"] = True
            report["meridian_flip"]["started_at"] = iso(timestamp)
            report["meridian_flip"]["operations"].append(
                {
                    "timestamp": iso(timestamp),
                    "operation": "mount_flip_started",
                }
            )

        if MERIDIAN_FLIP_FINISH_PATTERN.search(message):
            report["meridian_flip"]["executed"] = True
            report["meridian_flip"]["completed_at"] = iso(timestamp)
            report["meridian_flip"]["operations"].append(
                {
                    "timestamp": iso(timestamp),
                    "operation": "mount_flip_completed",
                }
            )

    if parsed_records == 0:
        raise ValueError("No SharpCap records were parsed.")

    if current_autofocus is not None:
        current_autofocus["status"] = "unfinished"

    for key, execution in current_thermal.items():
        if execution is not None:
            execution["status"] = "unfinished"

    session_start = min(timestamps)
    session_end = max(timestamps)
    elapsed = duration(session_start, session_end)

    report["session"] = {
        "start": iso(session_start),
        "end": iso(session_end),
        "duration_seconds": elapsed,
        "duration": duration_text(elapsed),
        "parsed_record_count": parsed_records,
    }

    report["capture"]["captured_file_count"] = len(
        report["capture"]["captured_files"]
    )
    report["capture"]["captured_files"] = report["capture"][
        "captured_files"
    ][-100:]

    report["sequence"]["progress_update_count"] = len(
        report["sequence"]["progress_updates"]
    )
    report["sequence"]["progress_updates"] = report["sequence"][
        "progress_updates"
    ][-100:]

    report["guiding"]["dither_request_count"] = len(
        report["guiding"]["dither_requests"]
    )
    report["guiding"]["dither_requests"] = report["guiding"][
        "dither_requests"
    ][-100:]

    report["focus"]["autofocus_run_count"] = len(
        report["focus"]["autofocus_runs"]
    )

    for bucket in report["thermal_corrections"].values():
        bucket["execution_count"] = len(bucket["executions"])

    return report


def build_focus_rows(report: dict[str, Any]) -> list[dict[str, str]]:
    """Create focus and thermal correction rows for CSV/text tables."""
    rows: list[dict[str, str]] = []

    for run in report["focus"]["autofocus_runs"]:
        result = run.get("result") or {}
        scan_result = run.get("scan_result") or {}
        moves = run.get("moves") or []

        start_move = next(
            (
                item
                for item in moves
                if item.get("type") == "overshoot_start"
            ),
            {},
        )
        final_move = next(
            (
                item
                for item in reversed(moves)
                if item.get("type") == "overshoot_finish"
            ),
            {},
        )

        start_position = start_move.get("from_position")
        final_position = (
            final_move.get("target_position")
            or start_move.get("target_position")
        )

        correction_steps = (
            final_position - start_position
            if start_position is not None and final_position is not None
            else None
        )

        if run.get("mode") == "offset":
            parameters = (
                f"Offset {run.get('offset_min')}..{run.get('offset_max')}; "
                f"{run.get('configured_steps')} steps; "
                f"backlash {run.get('backlash_steps')}"
            )
        else:
            parameters = (
                f"Range {run.get('range_start')}..{run.get('range_end')}; "
                f"{run.get('configured_steps')} steps; "
                f"backlash {run.get('backlash_steps')}"
            )

        notes: list[str] = []

        if start_move:
            notes.append(
                f"Overshoot {start_move.get('overshoot_steps')} "
                f"via {start_move.get('via_position')}"
            )

        if run.get("failure_reason"):
            notes.append(run["failure_reason"])

        rows.append(
            {
                "timestamp": run.get("started_at") or "",
                "source": "SharpCap autofocus",
                "status": run.get("status") or "",
                "parameters": parameters,
                "start_position": str(start_position or ""),
                "best_position": str(
                    result.get("best_focus_position")
                    or scan_result.get("position")
                    or ""
                ),
                "final_position": str(final_position or ""),
                "correction_steps": str(
                    correction_steps
                    if correction_steps is not None
                    else ""
                ),
                "temperature_celsius": str(
                    result.get("focuser_temperature_celsius") or ""
                ),
                "focus_score": str(scan_result.get("score") or ""),
                "fit_variance_percent": str(
                    scan_result.get("variance_percent") or ""
                ),
                "duration": run.get("duration") or "",
                "notes": "; ".join(notes),
            }
        )

    thermal_labels = {
        "main_telescope": "C8 thermal script",
        "guide_telescope": "ED50 thermal script",
    }

    for key, label in thermal_labels.items():
        bucket = report["thermal_corrections"][key]

        for execution in bucket["executions"]:
            command = execution.get("command") or bucket["command"]
            parameters = execution.get("parameters") or ""
            command_line = f"{command} {parameters}".strip()

            rows.append(
                {
                    "timestamp": execution.get("started_at") or "",
                    "source": label,
                    "status": execution.get("status") or "",
                    "parameters": command_line,
                    "start_position": "",
                    "best_position": "",
                    "final_position": "",
                    "correction_steps": "",
                    "temperature_celsius": "",
                    "focus_score": "",
                    "fit_variance_percent": "",
                    "duration": execution.get("duration") or "",
                    "notes": execution.get("script") or "",
                }
            )

    return sorted(rows, key=lambda row: row["timestamp"])


def write_focus_reports(
    report: dict[str, Any],
    created_at: str,
) -> tuple[Path, Path]:
    """Write focus correction reports as CSV and formatted text."""
    rows = build_focus_rows(report)

    csv_path = REPORTS_DIRECTORY / (
        f"sharpcap_focus_corrections_{created_at}.csv"
    )
    text_path = REPORTS_DIRECTORY / (
        f"sharpcap_focus_corrections_{created_at}.txt"
    )

    fields = [
        "timestamp",
        "source",
        "status",
        "parameters",
        "start_position",
        "best_position",
        "final_position",
        "correction_steps",
        "temperature_celsius",
        "focus_score",
        "fit_variance_percent",
        "duration",
        "notes",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    headers = [
        ("Timestamp", "timestamp"),
        ("Source", "source"),
        ("Status", "status"),
        ("Parameters", "parameters"),
        ("Start", "start_position"),
        ("Best", "best_position"),
        ("Final", "final_position"),
        ("Delta", "correction_steps"),
        ("Temp C", "temperature_celsius"),
        ("Score", "focus_score"),
        ("Fit %", "fit_variance_percent"),
        ("Duration", "duration"),
        ("Notes", "notes"),
    ]

    widths = {
        key: max(
            [len(title)] + [
                len(str(row.get(key, "")))
                for row in rows
            ]
        )
        for title, key in headers
    }

    output = [
        "SharpCap Focus Corrections",
        "=" * len("SharpCap Focus Corrections"),
        "",
        " | ".join(
            title.ljust(widths[key])
            for title, key in headers
        ),
        "-+-".join(
            "-" * widths[key]
            for _, key in headers
        ),
    ]

    if rows:
        for row in rows:
            output.append(
                " | ".join(
                    str(row.get(key, "")).ljust(widths[key])
                    for _, key in headers
                )
            )
    else:
        output.append("No autofocus or thermal corrections found.")

    text_path.write_text(
        "\n".join(output) + "\n",
        encoding="utf-8",
    )

    return csv_path, text_path


def write_reports(
    report: dict[str, Any],
) -> tuple[Path, Path, Path]:
    """Write the JSON report and the two focus correction tables."""
    REPORTS_DIRECTORY.mkdir(parents=True, exist_ok=True)

    created_at = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = REPORTS_DIRECTORY / (
        f"sharpcap_session_report_{created_at}.json"
    )
    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    csv_path, text_path = write_focus_reports(report, created_at)

    return json_path, csv_path, text_path


def print_summary(
    report: dict[str, Any],
    json_path: Path,
    csv_path: Path,
    text_path: Path,
) -> None:
    """Print a concise session summary."""
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
    print(f"Target: {', '.join(capture['targets']) or 'Not detected'}")
    print(f"Camera: {', '.join(capture['cameras']) or 'Not detected'}")
    print(
        "Science exposure: "
        f"{', '.join(str(value) for value in capture['science_exposure_seconds']) or 'Not detected'} s"
    )
    print(
        "Frames: "
        f"{sequence['latest_completed_frames'] or 0}/"
        f"{sequence['planned_frames'] or 'Not detected'}"
    )
    print(f"Dither requests: {guiding['dither_request_count']}")
    print(f"Autofocus runs: {focus['autofocus_run_count']}")
    print(
        "Main thermal corrections: "
        f"{thermal['main_telescope']['execution_count']}"
    )
    print(
        "Guide thermal corrections: "
        f"{thermal['guide_telescope']['execution_count']}"
    )
    print(
        "Meridian flip executed: "
        f"{'yes' if meridian['executed'] else 'no'}"
    )
    print(f"Warnings: {diagnostics['warning_count']}")
    print(f"Errors: {diagnostics['error_count']}")
    print(f"Fatal records: {diagnostics['fatal_count']}")
    print(f"JSON report: {json_path}")
    print(f"Focus corrections CSV: {csv_path}")
    print(f"Focus corrections table: {text_path}")


def main() -> int:
    """Run the analyzer using the required local configuration."""
    try:
        properties = read_properties(CONFIG_PATH)
        configured_path = properties.get("sharpcap.logs.path")

        if not configured_path:
            raise KeyError(
                "Missing required property: sharpcap.logs.path"
            )

        latest_log = find_latest_log(Path(configured_path))
        report = build_report(latest_log)
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