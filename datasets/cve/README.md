# CVE Dataset

Place CVE-related documents here in `.txt` or `.md` format.

## Suggested Content

- NVD CVE descriptions exported as text files
- CVE advisories from software vendors (Apache, OpenSSL, etc.)
- Security bulletin summaries

## Example: Downloading CVE Data

You can use the NVD API to download CVE data in bulk:

```bash
# Download recent CVEs (JSON format) and convert to text
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100" \
  -o nvd_cves.json
```

Then use a script to extract descriptions into individual `.txt` files.
