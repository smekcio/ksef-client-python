from ksef_client.cli.config.schema import CliConfig, ProfileConfig


def test_profile_schema() -> None:
    cfg = CliConfig(
        active_profile="demo",
        profiles={"demo": ProfileConfig("demo", "DEMO", "url", "nip", "1")},
    )
    assert cfg.active_profile == "demo"
