# Contributing to Wilma

Thank you for your interest in contributing! This project welcomes contributions from the GenAI security community.

## How to Contribute

### Reporting Issues
- Check if the issue already exists
- Provide clear reproduction steps
- Include error messages and logs
- Specify your AWS region and Python version

### Suggesting Features
- Open an issue with the "enhancement" label
- Describe the use case and benefits
- Consider GenAI security implications

### Submitting Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and checks:
   ```bash
   pytest tests/                    # Run test suite
   ruff check src/ tests/          # Lint code
   bandit -r src/                  # Security scan
   ```
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/ethanolivertroy/wilma.git
cd wilma

# Install with development dependencies
pip install -e ".[dev]"

# Verify installation
wilma --help
```

### CI/CD Integration
All pull requests automatically run:
- **Tests** across Python 3.8, 3.9, 3.10, 3.11, 3.12
- **Linting** with ruff
- **Security scanning** with bandit
- **Type checking** with mypy
- **Coverage check** (minimum 80% required)

See `.github/workflows/test.yml` for details.

### Code Style
- Follow PEP 8
- Use meaningful variable names
- Add comments for complex logic
- Keep security in mind
- Code is automatically checked by ruff in CI/CD

### Testing
- All tests use mocked AWS services (no real AWS credentials needed)
- Test with different AWS configurations
- Verify standard mode and learning mode work
- Check JSON output format
- Aim for 80%+ test coverage

### Areas of Interest
- New GenAI attack patterns
- Additional AWS service integrations
- Performance improvements
- Documentation enhancements
- Internationalization

## License
By contributing, you agree that your contributions will be licensed under GPL v3.0.