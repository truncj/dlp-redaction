### DLP redaction of local JSON with Google Cloud DLP API

``` 
usage: redaction.py [-h] --path PATH --project-id PROJECT_ID --token TOKEN --request-type REQUEST_TYPE

optional arguments:
  -h, --help                  show this help message and exit
  --path PATH                  Path to input file
  --project-id PROJECT_ID      GCP project id
  --token TOKEN                GCP service account token
  --request-type REQUEST_TYPE  inspect or deidentify
```
---
#### Request-Type

`--request-type inspect` prints information about how the data is categorized by DLP

`--request-type deidentify` applies the deidentify_config masking for identified information and writes to `output/{file}-out.json`

---