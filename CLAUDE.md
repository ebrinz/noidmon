# MacOS Monitor Project Guidelines

## Running & Testing
- Run monitor: `source monitor_env/bin/activate && python macos-monitor.py`
- Run with config: `python macos-monitor.py --config config.json`
- Generate report: `python macos-monitor.py --report daily --format html`
- Run statusbar app: `python statusbar_monitor.py`
- Check monitor status: `./check_monitor.sh`
- Run single process version: `./run_monitor.sh`

## Code Style Guidelines
- Import order: standard library → third-party → local modules
- Module imports should be at the top of the file, with standard library imports first
- Use Python type hints where appropriate (function parameters and return values)
- Class names: CamelCase, functions/methods: snake_case, constants: UPPERCASE
- Use docstrings for all classes and methods following the format used in existing code
- Error handling: Use try/except blocks with specific exceptions, log errors appropriately
- All database operations should be properly committed and connections closed
- Logging: use the established logger with appropriate levels (info, warning, error)
- For user-facing messages, provide clear context and actionable information
- Format code with 4-space indentation and 80-character line limit