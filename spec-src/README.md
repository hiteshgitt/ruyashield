# RuyaShield spec sources

These scripts generate the five v2.0 deliverables in the parent folder from the plain-JS data modules.

| File | Contents |
|---|---|
| `data_core.js` | Audit, requirements, security reqs, roles/permissions, epics, decisions, NFRs, risks, phases, glossary |
| `data_stories.js` | User stories and Definition of Done |
| `data_tests.js` | QA / security / AI-eval test cases |
| `data_tech.js` | Technical blueprint content |
| `diagrams/*.mmd` | Mermaid sources (PNGs are committed alongside) |
| `gen.js` | Validates cross-references, then writes the .docx, three .xlsx and the blueprint .md |

```bash
npm install
npm run build            # writes to the parent folder (default /var/www/html/RuyaShield)
node gen.js /some/dir    # or to another folder
npm run diagrams         # only if a .mmd changed
```

`gen.js` exits 1 on any dangling ID (story→req, story→test, test→req). It prints the coverage gaps as JSON, and both lists should be empty.
