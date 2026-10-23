import pytest

from backend.app.main import app


@pytest.fixture(autouse=True)
def reset_api_rate_limiter_between_tests():
    app.state.rate_limiter.reset()
    yield
    app.state.rate_limiter.reset()
