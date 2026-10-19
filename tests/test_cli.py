from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import main as cli
from cyberassess.collector import CollectionError
from cyberassess.profiles import get_profile


ROOT = Path(__file__).resolve().parents[1]
GOLDEN = json.loads((ROOT / 'tests/fixtures/ubuntu_legacy_demo_report.json').read_text(encoding='utf-8'))


def invoke(*arguments):
    return subprocess.run(
        [sys.executable, str(ROOT / 'main.py'), *map(str, arguments)],
        cwd=ROOT, capture_output=True, text=True, encoding='utf-8',
        env={**os.environ, 'PYTHONIOENCODING': 'utf-8'}, timeout=60,
    )


def read_report(directory):
    paths = list(directory.glob('*.json'))
    assert len(paths) == 1
    assert len(list(directory.glob('*.html'))) == 1
    return json.loads(paths[0].read_text(encoding='utf-8'))


def test_legacy_demo_preserves_golden_json_and_console(tmp_path):
    destination = tmp_path / 'reports café'
    result = invoke('--demo', '--output', destination)
    assert result.returncode == 0, result.stderr
    assert read_report(destination) == GOLDEN
    assert 'CyberAssess Live Assessment\n===========================' in result.stdout
    assert 'Score:  54.3%\nPassed: 7\nFailed: 8\nErrors: 0' in result.stdout
    assert 'application' not in read_report(destination)
    assert 'JSON report:' in result.stdout and 'HTML report:' in result.stdout


def test_legacy_ssh_dispatch_and_json_remain_compatible(monkeypatch, tmp_path):
    calls = []
    bundle = {key: value for key, value in GOLDEN.items() if key != 'assessment'}

    class FakeSSH:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def collect(self):
            return bundle

    monkeypatch.setattr('cyberassess.collector.SSHCollector', FakeSSH)
    monkeypatch.chdir(ROOT)
    status = cli.main(['--host', 'authorized.example.test', '--user', 'auditor', '--key', '/approved/key', '--port', '2222', '--accept-new-host', '--output', str(tmp_path)])
    assert status == 0
    assert calls == [{'host': 'authorized.example.test', 'username': 'auditor', 'key_file': '/approved/key', 'port': 2222, 'accept_new_host': True}]
    assert read_report(tmp_path) == GOLDEN


def test_legacy_connection_error_returns_two(monkeypatch, tmp_path, capsys):
    class FailingSSH:
        def __init__(self, **kwargs):
            pass

        def collect(self):
            raise CollectionError('Connection refused')

    monkeypatch.setattr('cyberassess.collector.SSHCollector', FailingSSH)
    monkeypatch.chdir(ROOT)
    assert cli.main(['--host', 'authorized.example.test', '--user', 'auditor', '--key', '/approved/key', '--output', str(tmp_path)]) == 2
    assert 'ERROR: Connection refused' in capsys.readouterr().out
    assert not list(tmp_path.iterdir())


def test_default_missing_live_arguments_still_errors():
    result = invoke()
    assert result.returncode == 2
    assert 'Live mode requires --host, --user and --key.' in result.stderr


@pytest.mark.parametrize(('profile_id', 'count'), [('ubuntu', 15), ('windows', 13), ('macos', 12)])
def test_profile_demo_cli(profile_id, count, tmp_path):
    result = invoke('--profile', profile_id, '--demo', '--output', tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    report = read_report(tmp_path)
    assert report['profile']['id'] == profile_id
    assert report['assessment']['total_controls'] == count
    assert report['assessment_mode'] == 'demo'
    assert report['application']['version'] == '2.0.0'
    assert 'Assessment in progress...' in result.stdout
    assert 'Scor' in result.stdout
    assert report['assessment']['results'][0]['profile'] == profile_id


def test_explicit_ubuntu_ssh_uses_original_collector(monkeypatch, tmp_path):
    calls = []

    class FakeSSH:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def collect(self):
            return {key: value for key, value in GOLDEN.items() if key != 'assessment'}

    monkeypatch.setattr('cyberassess.collector.SSHCollector', FakeSSH)
    assert cli.main(['--profile', 'ubuntu', '--host', 'authorized.example.test', '--user', 'auditor', '--key', '/approved/key', '--output', str(tmp_path)]) == 0
    report = read_report(tmp_path)
    assert calls[0]['host'] == 'authorized.example.test'
    assert report['assessment']['compliance_score'] == GOLDEN['assessment']['compliance_score']
    assert report['assessment_mode'] == 'ssh'
    for result, original in zip(report['assessment']['results'], GOLDEN['assessment']['results']):
        assert {key: result[key] for key in original} == original


@pytest.mark.parametrize('flags', [[], ['--local']])
def test_auto_detect_dispatch_is_local(monkeypatch, tmp_path, flags):
    calls = []
    monkeypatch.setattr(cli, 'detect_local_profile', lambda: 'windows')

    def fake_collect(profile_id, args, mode):
        calls.append((profile_id, mode))
        return get_profile('windows').load_demo()

    monkeypatch.setattr(cli, '_collect_profile', fake_collect)
    assert cli.main(['--auto-detect', *flags, '--output', str(tmp_path)]) == 0
    assert calls == [('windows', 'local')]
    assert read_report(tmp_path)['assessment_mode'] == 'local'


def test_local_mismatch_prevents_collection(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, 'detect_local_profile', lambda: 'macos')
    monkeypatch.setattr(cli, '_collect_profile', lambda *args: pytest.fail('Should not collect'))
    with pytest.raises(SystemExit) as error:
        cli.main(['--profile', 'windows', '--local', '--output', str(tmp_path)])
    assert error.value.code == 2
    assert not list(tmp_path.iterdir())


def test_unsupported_local_platform_is_explained(monkeypatch, capsys):
    def unsupported():
        raise ValueError('Unsupported local platform: test OS')

    monkeypatch.setattr(cli, 'detect_local_profile', unsupported)
    with pytest.raises(SystemExit) as error:
        cli.main(['--auto-detect'])
    assert error.value.code == 2
    assert 'Unsupported local platform' in capsys.readouterr().err


@pytest.mark.parametrize('arguments', [
    ['--profile', 'unknown', '--demo'],
    ['--profile', 'windows'],
    ['--profile', 'macos', '--host', 'host', '--user', 'auditor', '--key', '/key'],
    ['--profile', 'ubuntu', '--demo', '--local'],
    ['--profile', 'ubuntu', '--auto-detect'],
    ['--profile', 'ubuntu', '--local', '--host', 'host'],
    ['--profile', 'ubuntu', '--demo', '--key', '/key'],
])
def test_invalid_profile_modes_fail_before_live_collection(arguments, tmp_path):
    result = invoke(*arguments, '--output', tmp_path)
    assert result.returncode == 2
    assert not list(tmp_path.iterdir())


def test_profile_listing_and_version_do_not_collect():
    listing = invoke('--list-profiles')
    assert listing.returncode == 0
    for name in ('ubuntu', 'windows', 'macos'):
        assert name in listing.stdout
    version = invoke('--version')
    assert version.returncode == 0
    assert version.stdout.strip() == 'CyberAssess 2.0.0'


@pytest.mark.parametrize(('profile_id', 'module', 'class_name'), [
    ('ubuntu', 'ubuntu', 'UbuntuLocalCollector'),
    ('windows', 'windows', 'WindowsCollector'),
    ('macos', 'macos', 'MacOSCollector'),
])
def test_explicit_local_profile_uses_selected_collector(monkeypatch, tmp_path, profile_id, module, class_name):
    import importlib
    selected = importlib.import_module(f'cyberassess.collectors.{module}')
    calls = []

    class FakeLocal:
        def collect(self):
            calls.append(profile_id)
            return get_profile(profile_id).load_demo()

    monkeypatch.setattr(selected, class_name, FakeLocal)
    monkeypatch.setattr(cli, 'detect_local_profile', lambda: profile_id)
    assert cli.main(['--profile', profile_id, '--local', '--output', str(tmp_path)]) == 0
    assert calls == [profile_id]
    assert read_report(tmp_path)['assessment_mode'] == 'local'


def test_local_collection_failure_returns_two(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, 'detect_local_profile', lambda: 'windows')

    def fail(*args):
        raise CollectionError('Native collection unavailable')

    monkeypatch.setattr(cli, '_collect_profile', fail)
    assert cli.main(['--local', '--output', str(tmp_path)]) == 2
    assert 'ERROR: Native collection unavailable' in capsys.readouterr().out
    assert not list(tmp_path.iterdir())


def test_missing_profile_assets_are_explained(monkeypatch, tmp_path, capsys):
    from dataclasses import replace
    missing = replace(get_profile('windows'), controls_path=tmp_path / 'missing.json')
    monkeypatch.setattr(cli, 'get_profile', lambda profile_id: missing)
    assert cli.main(['--profile', 'windows', '--demo', '--output', str(tmp_path / 'reports')]) == 2
    assert 'ERROR: Could not load the selected baseline' in capsys.readouterr().out


def test_registry_errors_are_explained(monkeypatch, tmp_path, capsys):
    from dataclasses import replace
    missing = replace(get_profile('windows'), controls_path=tmp_path / 'missing.json')
    monkeypatch.setattr(cli, 'list_profiles', lambda: (missing,))
    assert cli.main(['--list-profiles']) == 2
    assert 'ERROR: Could not load the baseline registry' in capsys.readouterr().out


def test_unknown_local_collector_is_not_silently_routed():
    from argparse import Namespace
    with pytest.raises(CollectionError, match='No local collector is registered'):
        cli._collect_profile('future-profile', Namespace(), 'local')


def test_complete_legacy_console_output_is_preserved(tmp_path):
    import re
    expected = (ROOT / 'tests/fixtures/ubuntu_legacy_demo_stdout.txt').read_text(encoding='utf-8')
    result = invoke('--demo', '--output', tmp_path)
    assert result.returncode == 0
    normalized = re.sub(r'^(JSON|HTML) report: .+$', r'\1 report: <generated path>', result.stdout, flags=re.M)
    assert normalized == expected
