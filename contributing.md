# Contributing

Contributions to dep-hallucinator are welcome.

## Setup

```bash
git clone https://github.com/serhanwbahar/dep-hallucinator.git
cd dep-hallucinator
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,test]"
```

## Testing

```bash
# Run tests
make test

# With coverage
make coverage

# Specific tests
pytest tests/test_core.py -v
```

## Code Quality

```bash
# Format code
make format

# Lint
make lint

# Type check
make type-check
```

## Development Areas

### Current Status
- ✅ Core parsing and CLI
- ✅ Registry integration
- ✅ Heuristic scoring
- ✅ Machine learning models
- 🚧 Threat intelligence database

### Contribution Opportunities

**High Priority:**
- ML model improvements
- Additional language support
- Performance optimization
- Test coverage expansion

**Good First Issues:**
- Improve error messages and user feedback
- Add support for more package managers
- Enhance test coverage for edge cases
- Performance optimizations for large files

## Code Guidelines

**Python:**
- Python 3.8+ with type hints
- Black formatting (88 chars)
- Async for I/O operations
- Guard clauses for validation

**Example:**
```python
async def analyze_package(package_info: PackageInfo) -> AnalysisResult:
    if not package_info or not package_info.exists:
        return AnalysisResult(error="Invalid package")
    
    try:
        features = extract_features(package_info)
        prediction = await model.predict(features)
        return AnalysisResult(
            confidence=prediction.confidence,
            probability=prediction.probability
        )
    except Exception as e:
        return AnalysisResult(error=f"Analysis failed: {e}")
```

## Security

Since this is a security tool:
- Validate all external inputs
- Use secure defaults (HTTPS, timeouts)
- Respect API rate limits
- Never expose sensitive data in errors
- Keep dependencies minimal and updated

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Update documentation if needed
6. Submit pull request

## Architecture

```
Input → Parser → Registry Check → Heuristics → ML Analysis → Risk Assessment → Report
```

**Components:**
- **Parsers**: Extract dependencies from files
- **Registry Clients**: Query package registries
- **Heuristics**: Analyze package characteristics
- **ML Engine**: Pattern recognition models
- **Scanner**: Orchestrates analysis pipeline
- **Reporter**: Generate scan results

## Testing Guidelines

- Unit tests for individual components
- Integration tests for full workflows
- Mock external API calls
- Test edge cases and error conditions
- Maintain >85% coverage

## Documentation

- Update README for new features
- Add docstrings for public APIs
- Include examples for complex functionality
- Keep docs concise and practical 