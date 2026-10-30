from woozies_proxy.settings import DEFAULT_ALLOWED_APIS, ProxySettings


def test_allowed_apis_default(monkeypatch):
    monkeypatch.delenv("ALLOWED_APIS", raising=False)
    assert ProxySettings.from_env(env_file=None).allowed_apis == DEFAULT_ALLOWED_APIS


def test_app_ids_from_env_lists(monkeypatch):
    monkeypatch.setenv("IOS_BUNDLE_IDS", "com.acme.one, com.acme.two")
    monkeypatch.setenv("ANDROID_PACKAGES", "com.acme.android")
    settings = ProxySettings.from_env(env_file=None)
    assert settings.ios_bundle_ids == ("com.acme.one", "com.acme.two")
    assert settings.android_packages == ("com.acme.android",)


def test_app_ids_fall_back_to_single_value_names(monkeypatch):
    monkeypatch.delenv("IOS_BUNDLE_IDS", raising=False)
    monkeypatch.delenv("ANDROID_PACKAGES", raising=False)
    monkeypatch.setenv("IOS_BUNDLE_ID", "com.acme.legacy")
    monkeypatch.setenv("ANDROID_PACKAGE", "com.acme.legacy.android")
    settings = ProxySettings.from_env(env_file=None)
    assert settings.ios_bundle_ids == ("com.acme.legacy",)
    assert settings.android_packages == ("com.acme.legacy.android",)


def test_allowed_apis_from_env(monkeypatch):
    monkeypatch.setenv("ALLOWED_APIS", "/localities/nearby/, distance/route/json")
    assert ProxySettings.from_env(env_file=None).allowed_apis == (
        "localities/nearby",
        "distance/route/json",
    )
