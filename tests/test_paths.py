# tests/test_paths.py - Where config and data live (extguard/paths.py)

import json

from extguard import paths, ttp_loader


class TestDataDir:
    def test_extguard_home_env_is_used(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EXTGUARD_HOME", str(tmp_path))
        assert paths.data_dir() == tmp_path
        assert paths.quarantine_root() == tmp_path / "quarantine"
        assert paths.queue_file() == tmp_path / "remediation_queue.jsonl"
        assert paths.ttp_user_dir() == tmp_path / "ttp_library"

    def test_specific_overrides_win(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EXTGUARD_QUARANTINE", str(tmp_path / "q"))
        monkeypatch.setenv("EXTGUARD_TTP_DIR", str(tmp_path / "t"))
        assert paths.quarantine_root() == tmp_path / "q"
        assert paths.ttp_user_dir() == tmp_path / "t"

    def test_nothing_points_inside_the_package(self):
        """Data inside site-packages is lost on reinstall (the v0.2.0 layout)."""
        for location in (paths.quarantine_root(), paths.queue_file(), paths.ttp_user_dir()):
            assert paths.PACKAGE_DIR not in location.parents


class TestFindConfig:
    def _write(self, path, section):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"virustotal": section}))
        return path

    def test_no_config_anywhere(self):
        assert paths.find_config() is None
        assert paths.load_config_section("virustotal") is None

    def test_current_directory_is_found(self, tmp_path):
        # conftest chdir()s into tmp_path
        self._write(tmp_path / "extguard.conf.json", {"enabled": True, "_comment": "x"})
        assert paths.load_config_section("virustotal") == {"enabled": True}

    def test_env_var_beats_current_directory(self, tmp_path, monkeypatch):
        self._write(tmp_path / "extguard.conf.json", {"source": "cwd"})
        env_cfg = self._write(tmp_path / "elsewhere" / "cfg.json", {"source": "env"})
        monkeypatch.setenv("EXTGUARD_CONFIG", str(env_cfg))
        assert paths.load_config_section("virustotal") == {"source": "env"}

    def test_home_is_the_last_resort(self, tmp_path, monkeypatch):
        home_cfg = paths.data_dir() / "extguard.conf.json"
        self._write(home_cfg, {"source": "home"})
        assert paths.load_config_section("virustotal") == {"source": "home"}

    def test_explicit_missing_path_is_not_silently_replaced(self, tmp_path):
        self._write(tmp_path / "extguard.conf.json", {"source": "cwd"})
        assert paths.load_config_section("virustotal", explicit=tmp_path / "nope.json") is None

    def test_malformed_config_is_none(self, tmp_path):
        (tmp_path / "extguard.conf.json").write_text("{broken")
        assert paths.load_config_section("virustotal") is None


class TestTtpRoot:
    def test_packaged_library_is_used_before_any_sync(self):
        assert ttp_loader.default_ttp_root() == paths.packaged_ttp_dir()
        assert any(paths.packaged_ttp_dir().rglob("*.md"))

    def test_synced_library_takes_over(self):
        user_dir = paths.ttp_user_dir()
        user_dir.mkdir(parents=True)
        (user_dir / "intel.md").write_text("# synced intel")
        assert ttp_loader.default_ttp_root() == user_dir
        assert "synced intel" in ttp_loader.load_ttp_library()
