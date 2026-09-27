# SharpCap Session Analyzer

A Python tool for analyzing SharpCap session logs and producing an operational capture summary: exposures, dithering, autofocus, thermal focus corrections, meridian flips, guiding recovery, and session issues.

## Features

- Detects the session target, camera, filters, frame types, and exposures.
- Summarizes science and auxiliary exposures, capture progress, dithering, and autofocus.
- Analyzes meridian-flip configuration and execution, including guiding stop/recovery and post-flip plate solves.
- Correlates SharpCap thermal-focus script invocations with Focus Sequencer logs.
- Generates JSON, CSV, and TXT reports under `reports/`.
- Classifies diagnostics so the console shows only actionable errors while preserving the total warning count and the complete detail in the JSON report.

## Requirements

- Python 3.10 or later.
- A SharpCap log file (`Log_*.log`).
- Optionally, Focus Sequencer logs to enrich thermal-correction data.

No external dependencies are required for basic use.

## Installation

```powershell
git clone https://github.com/davidglt/sharpcap-sequence-analyzer.git
cd sharpcap-sequence-analyzer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## Configuration

Copy the example file and adapt the paths to your installation:

```powershell
Copy-Item sharpcap_sequence_analyzer.properties.example sharpcap_sequence_analyzer.properties
```

The local `sharpcap_sequence_analyzer.properties` file should not be committed. Configure the following as needed:

- The SharpCap log file path or the directory that contains SharpCap logs.
- The directory containing Focus Sequencer logs.
- The names of the primary-tube and guide-tube thermal-correction scripts.

## Usage

Run the analyzer from the project directory:

```powershell
python sharpcap_sequence_analyzer.py
```

For reproducible analysis of a specific log, or to use a different configuration
and output directory:

```powershell
python sharpcap_sequence_analyzer.py --log C:\path\to\Log_2026-01-01T00_00_00-123.log
python sharpcap_sequence_analyzer.py --config C:\path\analyzer.properties --reports-dir .\output
```

The program prints a console summary and writes three timestamped artifacts to `reports/`:

```text
sharpcap_session_report_YYYYMMDD_HHMMSS.json
sharpcap_focus_corrections_YYYYMMDD_HHMMSS.csv
sharpcap_focus_corrections_YYYYMMDD_HHMMSS.txt
```

## Thermal focus corrections

The analyzer detects thermal-focus script executions started by SharpCap. When it finds a matching block in a Focus Sequencer log, it adds the available telemetry:

- `T`: focuser or associated-sensor temperature in °C.
- `dT`: temperature change relative to the reference, in °C.
- `TCF`: thermal coefficient used to calculate compensation, typically in focuser steps/°C.
- `corr`: requested correction in focuser steps.
- `pos`: focuser position as `before->after`.
- `backlash`: whether the move required backlash compensation.
- `update`: position or model update status.
- `r`: execution result, such as `ok`, `min_correction`, or `interrupted`.

Compact console example:

```text
[22:43:00.729633] T=22.3 C; dT=-2.25 C; TCF=-60.29; corr=136; pos=14430->14566; backlash=False; update=ok; r=ok
```

`r=min_correction` means that Focus Sequencer evaluated a correction but decided not to move the focuser because it did not reach the configured threshold or because the required movement was in the backlash direction. These events remain in the reports. Depending on the format of the line emitted by Focus Sequencer, some optional fields may be unavailable and displayed as `None`.

### Primary and guide tubes

Corrections are separated between the primary and guide tubes according to the script invoked by SharpCap. To enrich both workflows, keep distinct Focus Sequencer logs using the naming convention configured for your installation. If no matching log block exists for an execution—for example, when analyzing a session recorded before separate guide logs were introduced—the analyzer reports `no_matching_focus_sequencer_execution`.

## Diagnostics

The console is designed for fast operational review:

- It shows diagnostics classified as actionable errors.
- It shows the total warning count without printing every individual warning.
- It shows the total number of visible errors and fatal records.
- It retains all diagnostics, including warnings, expected events, and duplicate detail records, in the JSON report.

Events normally suppressed from console output include unavailable optional camera drivers, unsupported ASCOM properties, expected single-frame capture cancellations during a meridian flip, and errors explicitly ignored by a sequence.

Two examples of actionable errors are:

- `autofocus_no_solution`: SharpCap could not find a best-focus position within the scanned range.
- `focuser_connection`: the ASCOM focuser monitor reported a disconnection.

## Generated files

| File | Contents |
|---|---|
| `sharpcap_session_report_*.json` | Complete structured session report, including metrics, corrections, diagnostics, and the source log filename. |
| `sharpcap_focus_corrections_*.csv` | Thermal-correction table for filtering and analysis in a spreadsheet. |
| `sharpcap_focus_corrections_*.txt` | Human-readable thermal-correction table. |

## Limitations

- The analyzer interprets specific SharpCap and Focus Sequencer log formats; version or script changes may require pattern updates.
- Missing telemetry for an execution does not necessarily mean a focus failure; it can mean that the log did not contain the expected format or that an execution could not be correlated.
- Diagnostics are classified with known patterns. Consult the JSON report for an unexpected issue or to review all warnings.

## Author

David González López-Tercero

## License

Copyright © 2026 David González López-Tercero.

This project is licensed under the GNU General Public License v3.0 or later
(GPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.
