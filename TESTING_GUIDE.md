# Quick Test Guide for SSHvigil

## Running All Tests

```bash
# Run all tests with verbose output
pytest tests/ -v

# Run all tests with summary only
pytest tests/ -q

# Run specific test file
pytest tests/test_edge_cases.py -v
pytest tests/test_security.py -v
pytest tests/test_stress.py -v

# Run tests with coverage report
pytest tests/ --cov=. --cov-report=html

# Run only fast tests (exclude stress tests)
pytest tests/ -v -m "not slow"
```

## Test Categories

### 1. Edge Cases (31 tests) - ~0.4s
Tests boundary conditions, malformed inputs, special characters
```bash
pytest tests/test_edge_cases.py -v
```

### 2. Security Tests (17 tests) - ~0.3s
Tests injection attacks, path traversal, security vulnerabilities
```bash
pytest tests/test_security.py -v
```

### 3. Stress Tests (16 tests) - ~0.7s
Tests performance with large datasets and extreme conditions
```bash
pytest tests/test_stress.py -v
```

### 4. Bug Tests (11 tests) - ~0.2s
Tests for specific bugs found during analysis
```bash
pytest tests/test_bug_findings.py -v
```

### 5. Integration Tests (3 tests) - ~0.5s
Tests end-to-end functionality
```bash
pytest tests/test_integration.py -v
```

### 6. Unit Tests (6 tests) - ~0.1s
Tests individual components
```bash
pytest tests/test_config.py tests/test_parser.py tests/test_detector.py -v
```

## Quick Health Check

Run this to verify everything works:
```bash
pytest tests/ -x  # Stop on first failure
```

## Results Summary

**Total:** 84 tests passing, 2 skipped
**Execution Time:** ~1.5 seconds
**Coverage:** Comprehensive

All tests pass ✅

## Static Analysis

```bash
# Code quality check
flake8 main.py parser.py config.py utils.py rules.py models.py

# Security scan
bandit -r . --exclude .venv,tests

# Type checking (if mypy is installed)
mypy main.py parser.py config.py utils.py
```

## Found Issues Summary

- **Critical:** 0 ❌
- **High:** 0
- **Medium:** 2 (bare except, tabs in rules.py)
- **Low:** 8 (unused imports/variables, style issues)

See `TESTING_REPORT.md` for full details.
