# Contributing

Contributions for additional providers, Agent versions, Linux distributions, and safer detection methods are welcome.

A new Agent entry should include:

1. an official vendor source;
2. exact package, service, process, and path identifiers;
3. a plain-language impact statement;
4. a risk classification (`optional` or `core`);
5. idempotent audit, disable, and remove behavior where possible;
6. smoke tests that do not modify the CI host;
7. no broad recursive deletion or remote pipe-to-shell commands.

Run before opening a pull request:

```bash
python3 -m py_compile cloud_agent_cleaner.py
python3 -m unittest -v tests/smoke.py
python3 cloud_agent_cleaner.py --audit
```
