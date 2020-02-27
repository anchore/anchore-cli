import json
import os
import random
import string
import time
import logging
import subprocess

import docker
from docker.errors import DockerException
import pytest

logger = logging.getLogger(__name__)


def use_environ():
    """
    In certain test environments, the necessary docker env vars are available
    and those should be used. This function checks for those and returns
    a boolean so that the docker client can be instantiated properly
    """
    for var in ['DOCKER_CERT_PATH', 'DOCKER_HOST', 'DOCKER_MACHINE_NAME', 'DOCKER_TLS_VERIFY']:
        if os.environ.get(var) is None:
            return False
    return True


def create_client():
    try:
        if use_environ():
            c = docker.from_env()
        else:
            c = docker.DockerClient(base_url='unix://var/run/docker.sock', version="auto")
        # XXX ?
        c.run = run(c)
        return c
    except DockerException as e:
        raise pytest.UsageError("Could not connect to a running docker socket: %s" % str(e))


@pytest.fixture(scope='session')
def client():
    return create_client()


def pytest_assertrepr_compare(op, left, right):
    if isinstance(left, ExitCode) and isinstance(right, ExitCode):
        return [
            "failure ExitCode(%s) %s ExitCode(%s)" % (left, op, right),
            "Exit status assertion failure, stdout and stderr context:",
            ] + [
            '   stdout: %s' % line for line in left.stdout.split('\n')
            ] + [
            '   stderr: %s' % line for line in left.stderr.split('\n')
        ]


def pytest_addoption(parser):
    """
    Do not Keep the container around and remove it after a test run. Useful
    only for the CI. When running locally a developer will probably want to
    keep the container around for easier/faster testing.
    """
    parser.addoption(
        "--nokeepalive", action="store_true",
        default=False, help="Do not keep docker container alive"
    )


def pytest_report_header(config):
    msg = []
    try:
        client = create_client()
        metadata = client.api.inspect_container('pytest_inline_scan')
    except docker.errors.NotFound:
        metadata = {'Config': {'Labels': {}}}
        msg = ['Docker: Anchore inline_scan container not running yet']
    except DockerException as e:
        msg = ['Anchore Version: Unable to connect to a docker socket']
        msg.append('Error: %s' % str(e))
        return msg

    labels = metadata['Config']['Labels']
    version = labels.get('version', 'unknown')
    commit = labels.get('anchore_commit', 'unknown')

    msg.extend([
       'Anchore Version: %s' % version,
       'Anchore Commit: %s' % commit
    ])
    return msg


def pytest_runtest_logreport(report):
    if report.failed:
        client = create_client()

        test_containers = client.containers.list(
            all=True,
            filters={"name": "pytest_inline_scan"})
        for container in test_containers:
            # XXX magical number! get the last 10 log lines
            log_lines = [
                ("Container ID: {!r}:".format(container.attrs['Id'])),
                ] + container.logs().decode('utf-8').split('\n')[-10:]
            report.longrepr.addsection('docker logs', os.linesep.join(log_lines))


@pytest.fixture(scope='session', autouse=True)
def inline_scan(client, request):
    # If the container is already running, this will return the running
    # container identified with `pytest_inline_scan`
    container = start_container(
        client,
        image='anchore/inline-scan',
        name='pytest_inline_scan',
        environment={},
        detach=True,
        ports={'8228/tcp': 8228}
    )

    no_keep_alive = request.config.getoption("--nokeepalive", False)
    if no_keep_alive:
        # Do not leave the container running and tear it down at the end of the session
        request.addfinalizer(lambda: teardown_container(client, container=container))

    return container


def teardown_container(client, container=None, name=None):
    container_name = name or container.name
    if name:
        container_name = name
    else:
        container_name = container.name
    containers = client.containers.list(all=True, filters={'name': container_name})
    # TODO: check if stop/remove can take a force=True param
    for available_container in containers:
        available_container.stop()
        available_container.remove()


def start_container(client, image, name, environment, ports, detach=True):
    """
    Start a container, wait for (successful) completion of entrypoint
    and raise an exception with container logs otherwise
    """
    try:
        container = client.containers.get(name)
        if container.status != 'running':
            container.start()
    except docker.errors.NotFound:
        container = client.containers.run(
            image=image,
            name=name,
            environment={},
            detach=True,
            ports=ports,
        )

    start = time.time()
    while time.time() - start < 70:
        out, err, code = call(
            ['anchore-cli', '--u', 'admin', '--p', 'foobar', 'system', 'status'],
        )
        if code == 0:
            # This path needs to be hit when the container is ready to be
            # used, if this is not reached, then an error needs to bubble
            # up
            return container
        time.sleep(2)

    # If 70 seconds passed and anchore-cli wasn't able to determine an OK
    # status from anchore-engine then failure needs to be raised with as much
    # logging as possible. Can't assume the container is healthy even if the
    # exit code is 0
    print("[ERROR][setup] failed to setup container")
    for line in out.split('\n'):
        print("[ERROR][setup][stdout] {}".format(line))
    for line in err.split('\n'):
        print("[ERROR][setup][stderr] {}".format(line))
    raise RuntimeError()


def remove_container(client, container_name):
    # remove any existing test container
    for test_container in client.containers.list(all=True):
        if test_container.name == container_name:
            test_container.stop()
            test_container.remove()


def run(client):
    def run_command(container_id, command):
        created_command = client.exec_create(container_id, cmd=command)
        result = client.exec_start(created_command)
        exit_code = client.exec_inspect(created_command)['ExitCode']
        if exit_code != 0:
            msg = 'Non-zero exit code (%d) for command: %s' % (exit_code, command)
            raise(AssertionError(result), msg)
        return result
    return run_command


class ExitCode(int):
    """
    For rich comparison in Pytest, the objects being compared can be
    introspected to provide more context to a failure. The idea here is that
    when the exit code is not expected, a custom Pytest hook can provide the
    `stderr` and `stdout` aside from just the exit code. The normal `int`
    behavior is preserved.
    """
    def __init__(self, code):
        self.code = code
        self.stderr = ''
        self.stdout = ''


def call(command, **kw):
    """
    Similar to ``subprocess.Popen`` with the following changes:

    * returns stdout, stderr, and exit code (vs. just the exit code)
    * logs the full contents of stderr and stdout (separately) to the file log

    By default, no terminal output is given, not even the command that is going
    to run.

    Useful when system calls are needed to act on output, and that same output
    shouldn't get displayed on the terminal.

    :param terminal_verbose: Log command output to terminal, defaults to False, and
                             it is forcefully set to True if a return code is non-zero
    :param split: Instead of returning output as a long string, split on newlines, and then also
                  split on whitespace. Useful when output keeps changing when tabbing on custom
                  lengths
    """
    terminal_verbose = kw.pop('terminal_verbose', False)
    command_msg = "Running command: %s" % ' '.join(command)
    logger.info(command_msg)
    env = kw.pop('env', None)
    split = kw.pop('split', False)
    existing_env = os.environ.copy()
    if env:
        for key, value in env.items():
            existing_env[key] = value

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        close_fds=True,
        env=existing_env,
        **kw
    )
    stdout_stream = process.stdout.read()
    stderr_stream = process.stderr.read()
    returncode = process.wait()
    if not isinstance(stdout_stream, str):
        stdout_stream = stdout_stream.decode('utf-8')
    if not isinstance(stderr_stream, str):
        stderr_stream = stderr_stream.decode('utf-8')

    if returncode != 0:
        # set to true so that we can log the stderr/stdout that callers would
        # do anyway
        terminal_verbose = True

    # the following can get a messed up order in the log if the system call
    # returns output with both stderr and stdout intermingled. This separates
    # that.
    # XXX Figure out a way to nicely log all this output via proper Pytest calls
    for line in stdout_stream.splitlines():
        logger.info('stdout', line, terminal_verbose)
    for line in stderr_stream.splitlines():
        logger.info('stderr', line, terminal_verbose)

    returncode = ExitCode(returncode)
    returncode.stderr = stderr_stream
    returncode.stdout = stdout_stream

    if split:
        stdout_stream = [line.split() for line in stdout_stream.split('\n')]
        stderr_stream = [line.split() for line in stderr_stream.split('\n')]

    return stdout_stream, stderr_stream, returncode


@pytest.fixture
def admin_call():
    def _call(command, **kw):
        if command[0] != 'anchore-cli':
            command.insert(0, 'anchore-cli')
        return call(
            command,
            env={'ANCHORE_CLI_USER': 'admin', 'ANCHORE_CLI_PASS': 'foobar'},
            **kw
        )
    return _call


def get_account(account_name, account_list):
    for account in account_list:
        if account['name'] == account_name:
            return account


def random_name():
    return ''.join(random.choice(string.ascii_lowercase) for i in range(8))


@pytest.fixture
def add_account(request, admin_call):
    def apply(account_name=None):
        if account_name is not None:
            # makes sure that for specific accounts, that those are not
            # present. This is problematic if that account was previously
            # created and it is currently in `deleting` state.
            for i in range(15):
                out, _, _ = admin_call(['--json', 'account', 'list'])
                account_list = json.loads(out)
                account = get_account(account_name, account_list)
                if account:
                    # created, possibly on deleting status
                    if account['state'] == 'deleting':
                        time.sleep(2)
                        continue
                    elif account['state'] == 'disabled':
                        # delete it because we need a clean slate
                        admin_call(['account', 'del', '--dontask', account_name])

                else:
                    break
        else:
            account_name = random_name()
        admin_call(['account', 'add', account_name])
        def finalizer(): # noqa
            admin_call(['account', 'disable', account_name])
            admin_call(['account', 'del', '--dontask', account_name])
        request.addfinalizer(finalizer)
        return account_name
    return apply
