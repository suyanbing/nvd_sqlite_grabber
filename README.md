# nvd_sqlite_grabber

Script that stores all cve and cpe information in a sqlite database.

## Installation:

```bash
git clone https://github.com/tinoloni/nvd_sqlite_grabber.git
cd nvd_sqlite_grabber
pip install -r requirements.txt
```

## Usage:

1. Just execute the python script
2. CVEs and its information will be imported in sqlite (vul.db).

## Database Structure

### cves
- cveid (PK)
- cvss
- access_vector
- access_complexity
- authentication
- confidentiality_impact
- integrity_impact
- availability_impact
- description
- published
- modified
- link

### cpe_cve
- id (PK)
- cpe (FK)
- cveid (FK)

### download_dates
- link (PK)
- last_download

Based on https://github.com/felmoltor/NVDparser


