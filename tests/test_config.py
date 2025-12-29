import json
from config import Config


def test_defaults_created_when_missing(tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg = Config(config_path=str(cfg_path))
    assert cfg.loaded_from_file is True
    data = json.loads(cfg_path.read_text())
    assert data["max_attempts"] == Config.DEFAULTS["max_attempts"]


def test_invalid_json_falls_back_to_defaults(tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text("{not-json}")
    cfg = Config(config_path=str(cfg_path))
    assert cfg.loaded_from_file is False
    assert cfg["max_attempts"] == Config.DEFAULTS["max_attempts"]


def test_unknown_and_type_invalid_keys_are_ignored(tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({
        "max_attempts": "five",  # wrong type
        "monitor_threshold": 15,
        "unknown_key": 1
    }))
    cfg = Config(config_path=str(cfg_path))
    # max_attempts stays default due to type error
    assert cfg["max_attempts"] == Config.DEFAULTS["max_attempts"]
    # monitor_threshold accepted
    assert cfg["monitor_threshold"] == 15
    # unknown_key ignored
    assert "unknown_key" not in cfg.to_dict()
