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

## Test Coverage

The current test coverage is focused on the following areas:

1. **Authentication Services**
   - `AuthService` class in `auth_service.py`
   - User login/logout functionality
   - Audit logging

2. **Utility Functions**
   - Cryptographic utilities in `crypto.py`
   - File utilities in `file_utils.py`

## Test Database

The tests use an in-memory SQLite database by default. You can configure a different test database by setting the `TEST_DATABASE_URI` environment variable.

### SQLite Compatibility Layer

The production application uses PostgreSQL, which has features not natively supported by SQLite (like UUID and JSON types). To allow tests to run with SQLite, we've implemented a compatibility layer in `conftest.py` that:

1. Defines custom type adapters for PostgreSQL-specific types:
   - `SqliteUUID`: Stores UUID values as strings in SQLite
   - `SqliteJSON`: Serializes/deserializes JSON data for SQLite
   - `SqliteTimestamp`: Handles PostgreSQL TIMESTAMP type in SQLite

2. Automatically replaces PostgreSQL types with SQLite-compatible versions at runtime

This allows the tests to run with SQLite without modifying the application models, which use PostgreSQL-specific types.

If you need to run tests with a real PostgreSQL database, set the `TEST_DATABASE_URI` environment variable:

```bash
# Run tests with PostgreSQL
TEST_DATABASE_URI="postgresql://user:password@localhost:5432/test_db" python run_tests.py
```

## Adding New Tests

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

## Best Practices

1. **Isolation**: Each test should be independent and not rely on the state from other tests.
2. **Mocking**: Use mocks to isolate the component being tested from its dependencies.
3. **Coverage**: Aim for high test coverage, especially for critical components.
4. **Edge Cases**: Test both normal and edge cases, including error handling.
5. **Readability**: Write clear test names and descriptions to make it easy to understand what's being tested.

## Continuous Integration

These tests are designed to be run in a CI environment. The test runner will exit with a non-zero status code if any tests fail, which can be used to trigger CI pipeline failures.
