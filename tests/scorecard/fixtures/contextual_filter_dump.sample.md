BEFORE
```json
{
  "schema_version": "contextual-filter-dump-v2",
  "candidates": [
    {"evidence_id": "candidate-1", "domain": "example.com", "title": "Example security incident"},
    {"evidence_id": "candidate-2", "domain": "example.com", "title": "Example product update"}
  ]
}
```
---
AFTER
```json
{
  "records": [
    {
      "evidence_id": "evidence-security-1",
      "domain": "example.com",
      "title": "Example security incident",
      "assertion_scope": "security_publication_context_only"
    }
  ]
}
```
