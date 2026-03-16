# Training Datasets for Cyvereign LoRA Fine-Tuning

Place your instruction-tuning datasets here in **JSONL format** (one JSON
object per line).

## Expected Format

Each line must be a JSON object with these fields:

```json
{"instruction": "...", "input": "...", "output": "..."}
```

| Field         | Required | Description |
|---------------|----------|-------------|
| `instruction` | ✅ Yes   | The task description / question |
| `input`       | ❌ No    | Optional additional context (e.g. code to analyse) |
| `output`      | ✅ Yes   | The expected model response |

## Example Records

```jsonl
{"instruction": "Identify the vulnerability in this Python code.", "input": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)", "output": "This code is vulnerable to SQL Injection (CWE-89). The user-supplied `user_id` is concatenated directly into the SQL query string without sanitisation.\n\nSecure fix:\n```python\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n```\nUsing a parameterised query ensures the database driver treats `user_id` as data, not executable SQL."}
{"instruction": "What is a buffer overflow and how can it be exploited?", "input": "", "output": "A buffer overflow (CWE-120) occurs when a program writes more data to a fixed-size buffer than it can hold, overwriting adjacent memory. Attackers exploit this to overwrite the return address on the stack, redirecting execution to attacker-controlled shellcode. Prevention: use safe string functions (strncpy, snprintf), enable stack canaries (-fstack-protector), and compile with ASLR/PIE enabled."}
```

## Recommended Data Sources

- OWASP WebGoat vulnerable application write-ups
- NVD CVE descriptions + manual mitigations
- Security research blog posts
- CTF write-ups (security challenge solutions)
- Secure coding guidelines (SEI CERT, MISRA)

## Converting Existing Data

```python
import json

# Convert a list of (question, answer) pairs to JSONL
pairs = [
    ("Explain SSRF", "Server-Side Request Forgery ..."),
]

with open("cybersec_instruct.jsonl", "w") as f:
    for instruction, output in pairs:
        f.write(json.dumps({"instruction": instruction, "output": output}) + "\n")
```
