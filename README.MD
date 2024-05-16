# OpenSearch Dashboard Request Extractor

This is a program designed to extract requests from OpenSearch dashboards.

## Description

This program is still in its early stages of development. It extracts charts request from OpenSearch dashboards. Please note that there are multiple warnings about secure connections being ignored.

## Warning

- This program has only been tested in OpenSearch environments.

## Usage
```bash
python opensearch_extractor.py <dashboard_url> -u <username> -p <password> -o <output_file>
```

## Dependencies

- `requests` library
- `argparse` library
- `json`     library
- `warnings` library
- `re`       library

## Installation

1. Clone the repository.
2. Install the required dependencies using the following command:

```bash
pip install -r requirements.txt
```

## Notes
- Make sure to use this program responsibly and only in authorized environments.
- Feedback and contributions are welcome.
- Feel free to adjust the content or format according to your preferences.

