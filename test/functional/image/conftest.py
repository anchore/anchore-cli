import pytest


@pytest.fixture(scope='session', autouse=True)
def add_image(session_admin_call):
    """
    This fixture will add the vulnerable image so that it can be analyzed, and only when
    tests executed in the `image` directory are called.

    TODO: Pin this to a specific digest
    """
    session_admin_call(['anchore-cli', 'image', 'add', 'alfredodeza/vulnerable'])
    session_admin_call(['anchore-cli', 'image', 'wait', 'alfredodeza/vulnerable'])
