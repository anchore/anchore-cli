# Functional Tests
This directory holds the functional tests for `anchore-cli`. It relies on the `anchore/inline-scan` container, the Python docker API, and Pytest. To avoid collision with unit tests in the parent directory do not run `pytest` directly from the top directory unless using the `--ignore=tests/functional` flag.

## Using pytest directly
Running tests directly with `pytest` is possible but requires having the `anchore/inline-scan` container available and docker running. The test setup talks to the docker socket.

If the `inline-scan` *is not running* the test session will start it up and bind the 8228 ports to localhost. After tests are completed, the container will not be destroyed. If you need the container to be destroyed there is a custom flag added in `tests/functional/conftest.py` that will do so: `--nokeepalive`.

Leaving the container running is the default behavior so that development can quickly re-run tests.

## Using tox
This functional test setup adds a separate `tox.ini` as well. The separate `tox.ini` file adds two factors: Python version and Anchore Engine version tag:

```ini
[tox]
envlist = py{27,35,36,37,38}-anchore_{0.6.0, 0.5.0, 0.5.1}
```

This allows `tox` to create a testing matrix so that it is possible to run a combination of Python versions and Anchore Engine. If running `tox` from the top level directory the configuration has to be passed in explicitly, otherwise the top-level `tox.ini` will get picked up. This is done with: `tox -c tests/functional/tox.ini` Ensure you use a specific environment to avoid running all the combinations at once. For example: `tox -c tests/functional/tox.ini -e py36-anchore_0.6.0`

As opposed to running with `pytest` directly, the `tox` implementation will pull the container required by the test. For example the test environment `py36-anchore_0.6.0` will call `docker pull anchore/inline-scan:v0.6.0`.

After pulling the container it will run `pytest` with `--nokeepalive` so that the container gets removed at the end of the test run.

