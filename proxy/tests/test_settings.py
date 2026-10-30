from woozies_proxy.settings import DEFAULT_ALLOWED_APIS, ProxySettings


def test_allowed_apis_default(monkeypatch):
    monkeypatch.delenv("ALLOWED_APIS", raising=False)
    assert ProxySettings.from_env(env_file=None).allowed_apis == DEFAULT_ALLOWED_APIS


def test_allowed_apis_from_env(monkeypatch):
    monkeypatch.setenv("ALLOWED_APIS", "/localities/nearby/, distance/route/json")
    assert ProxySettings.from_env(env_file=None).allowed_apis == (
        "localities/nearby",
        "distance/route/json",
    )
