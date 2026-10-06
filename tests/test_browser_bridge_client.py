import pytest

from tools.browser_bridge import agent, client, policy


def test_agent_cannot_open_the_native_file_picker():
    class Locator:
        clicked = False

        def count(self):
            return 1

        def is_visible(self):
            return True

        def is_enabled(self):
            return True

        def get_attribute(self, name):
            return "file" if name == "type" else None

        def click(self, **kwargs):
            self.clicked = True

    class Page:
        url = "http://127.0.0.1:7860/"

        def __init__(self):
            self.control = Locator()

        def get_by_role(self, *args, **kwargs):
            return self.control

    class Context:
        def __init__(self, page):
            self.pages = [page]

    page = Page()
    with pytest.raises(policy.PolicyError, match="File selection"):
        client.perform_action(
            page,
            Context(page),
            "http://127.0.0.1:7860",
            {"type": "click", "role": "button", "name": "Browse"},
        )
    assert not page.control.clicked


def test_action_result_redacts_secret_text_before_sharing():
    text = "API_KEY=privatevalue Bearer abcdefghijklmnop"
    result = policy.redact_sensitive_text(text)
    assert "privatevalue" not in result
    assert "abcdefghijklmnop" not in result

def test_relay_url_is_pinned_to_the_owned_https_service():
    assert agent.validate_relay_url(agent.DEFAULT_RELAY_URL) == agent.DEFAULT_RELAY_URL
    for value in (
        "http://cat-browser-bridge-2nnhh.zocomputer.io",
        "https://attacker.example",
        "https://cat-browser-bridge-2nnhh.zocomputer.io/other-path",
        "https://user@cat-browser-bridge-2nnhh.zocomputer.io",
    ):
        with pytest.raises(agent.BridgeError):
            agent.validate_relay_url(value)


def test_secret_fields_are_never_controlled():
    class Locator:
        filled = False

        def count(self):
            return 1

        def is_visible(self):
            return True

        def is_enabled(self):
            return True

        def get_attribute(self, name):
            return {"type": "text", "name": "openai_api_key"}.get(name)

        def fill(self, value, **kwargs):
            self.filled = True

    class Page:
        url = "http://127.0.0.1:7860/"

        def __init__(self):
            self.control = Locator()

        def get_by_label(self, *args, **kwargs):
            return self.control

    class Context:
        def __init__(self, page):
            self.pages = [page]

    page = Page()
    with pytest.raises(policy.PolicyError, match="Secret.*fields"):
        client.perform_action(
            page,
            Context(page),
            "http://127.0.0.1:7860",
            {"type": "fill", "name": "API key", "value": "test-value"},
        )
    assert not page.control.filled
