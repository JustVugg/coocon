# Contributing

Thanks for your interest in Coocon.

## Quick start

```bash
python3 -m py_compile coocon/__init__.py src/coocon_cli.py
cargo check
```

## Development guidelines

- Keep the CLI simple and user-centric.
- Avoid adding heavy dependencies without strong justification.
- Security changes should include a short rationale and any tradeoffs.
- Run the basic checks before opening a PR.

## Reporting issues

- Provide OS and Python version.
- Include the exact command and error output.
- Mention whether the daemon was running (`coocon doctor`).

