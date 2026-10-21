
# Real-TunnelBench

A GitHub Actions tool for static analysis of configuration text files.

## Features

- Downloads a public HTTP(S) text file.
- Recognizes supported URI schemes.
- Removes duplicate lines.
- Separates unrecognized lines.
- Generates a TXT output and a PDF summary.
- Runs manually through GitHub Actions.
- Uploads generated files as a workflow artifact.

## Limitations

This project performs static text analysis only. It does not connect
to configuration endpoints, test availability, measure latency or
throughput, or determine whether a configuration is operational.

Recognized URI schemes are classified by their textual structure.
This does not guarantee that a configuration is valid or functional.

## Usage

1. Open the repository's Actions tab.
2. Select "Real-TunnelBench Analysis".
3. Click "Run workflow".
4. Enter the public URL of a text file.
5. Start the workflow.
6. Open the completed run and download
   `real-tunnelbench-report` under Artifacts.

## Output files

- `accepted_configs.txt`: unique lines with recognized URI schemes.
- `rejected_lines.txt`: non-comment lines with unrecognized structure.
- `report.pdf`: summary statistics and scheme counts.

## Limits

- Input file limit: 5 MB.
- Download timeout: 20 seconds.
- Python: 3.12.

## License

Choose a license before distributing this project.
