# Crypto Hunter Testing Suite

This directory contains the testing suite for the Crypto Hunter application. The tests are organized into unit tests and integration tests.

## Test Structure

- `conftest.py`: Contains pytest fixtures used by the tests
- `test_*.py`: Unit tests for individual components
- `integration/`: Integration tests that test multiple components working together

## Running Tests

You can run the tests using the `run_tests.py` script in the project root directory:

```bash
# Run all tests
python run_tests.py

# Run only unit tests
python run_tests.py --unit

# Run only integration tests
python run_tests.py --integration

# Run tests with verbose output
python run_tests.py -v

# Generate coverage report
python run_tests.py --coverage

# Run a specific test file
python run_tests.py --test-path crypto_hunter_web/tests/test_auth_service.py
```

## Test Dependencies

The tests require the following dependencies:
- pytest
- pytest-cov (for coverage reports)

You can install these dependencies with:

```bash
pip install pytest pytest-cov
```

## Test Database

The tests use an in-memory SQLite database by default. You can configure a different test database by setting the `TEST_DATABASE_URI` environment variable.

## Writing New Tests

### Unit Tests

Unit tests should be placed in the `crypto_hunter_web/tests` directory with filenames starting with `test_`. Each test file should focus on testing a single component or module.

Example:
```python
# test_example.py
def test_some_function():
    result = some_function()
    assert result == expected_value
```

### Integration Tests

Integration tests should be placed in the `crypto_hunter_web/tests/integration` directory. These tests should focus on testing how multiple components work together.

Example:
```python
# integration/test_example_integration.py
def test_component_interaction(app, client):
    # Test how components interact
    response = client.post('/api/endpoint', json={'key': 'value'})
    assert response.status_code == 200
    # Check database state, etc.
```

### Fixtures

Common test fixtures are defined in `conftest.py`. You can add new fixtures there if they are needed by multiple test files.

## Continuous Integration

These tests are designed to be run in a CI environment. The test runner will exit with a non-zero status code if any tests fail, which can be used to trigger CI pipeline failures.