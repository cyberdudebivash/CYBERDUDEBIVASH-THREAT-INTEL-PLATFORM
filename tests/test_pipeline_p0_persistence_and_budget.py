"""Offline regression proof for the 2026-10-06 production pipeline incident."""
import io
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import safe_git_commit as git_sync
import deployment_convergence_validator as convergence

class Response:
    def __init__(self, value): self.value = value
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, size): return json.dumps(self.value).encode()

@pytest.mark.parametrize('existing', [False, True])
def test_ci_metadata_is_persisted_via_review_pr_not_direct_main(tmp_path, monkeypatch, existing):
    monkeypatch.setattr(git_sync, 'REPO_ROOT', tmp_path)
    monkeypatch.setenv('GITHUB_RUN_ID', '37490666334')
    monkeypatch.setenv('GITHUB_RUN_ATTEMPT', '1')
    calls = []
    monkeypatch.setattr(git_sync, 'run_git', lambda *args: calls.append(args) or subprocess.CompletedProcess(args, 0, 'a'*40))
    http = []
    def urlopen(req, **kwargs):
        http.append(req)
        return Response([{'number': 701}] if existing else []) if req.method == 'GET' else Response({'number': 701})
    monkeypatch.setattr(urllib.request, 'urlopen', urlopen)
    result = git_sync.publish_metadata_pr('offline-token', 'owner/repo')
    assert calls == [
        ('rev-parse', 'HEAD'),
        ('push', 'origin', 'HEAD:refs/heads/sentinel-generated/run-37490666334-1'),
        ('ls-remote', '--exit-code', 'origin', 'refs/heads/sentinel-generated/run-37490666334-1'),
    ]
    assert result['state'] == 'PERSISTED_REVIEW_PENDING' and result['main_updated'] is False
    assert result['remote_verified'] is True
    assert len(http) == (1 if existing else 2)
    if not existing:
        assert json.loads(http[-1].data)['draft'] is True
    assert json.loads((tmp_path/'data/health/git_sync_state.json').read_text()) == result

def test_rejected_metadata_branch_fails_without_api_or_false_success(tmp_path, monkeypatch):
    monkeypatch.setattr(git_sync, 'REPO_ROOT', tmp_path)
    monkeypatch.setenv('GITHUB_RUN_ID', '123')
    monkeypatch.setenv('GITHUB_RUN_ATTEMPT', '1')
    monkeypatch.setattr(git_sync, 'run_git', lambda *args: subprocess.CompletedProcess(args, 0, 'a'*40) if args[0] == 'rev-parse' else subprocess.CompletedProcess(args, 1))
    with pytest.raises(RuntimeError, match='branch push rejected'):
        git_sync.publish_metadata_pr('offline-token', 'owner/repo')
    assert not (tmp_path/'data/health/git_sync_state.json').exists()


def test_remote_branch_sha_mismatch_fails_before_pr_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr(git_sync, 'REPO_ROOT', tmp_path)
    monkeypatch.setenv('GITHUB_RUN_ID', '123')
    monkeypatch.setenv('GITHUB_RUN_ATTEMPT', '1')
    calls = []
    def run_git(*args):
        calls.append(args)
        if args[0] == 'rev-parse':
            return subprocess.CompletedProcess(args, 0, 'a'*40)
        if args[0] == 'push':
            return subprocess.CompletedProcess(args, 0, '')
        if args[0] == 'ls-remote':
            return subprocess.CompletedProcess(args, 0, 'b'*40 + '\trefs/heads/sentinel-generated/run-123-1\n')
        raise AssertionError(args)
    monkeypatch.setattr(git_sync, 'run_git', run_git)
    monkeypatch.setattr(
        urllib.request,
        'urlopen',
        lambda *a, **k: pytest.fail('GitHub PR API must not run when remote SHA is unverified'),
    )
    with pytest.raises(RuntimeError, match='remote verification failed'):
        git_sync.publish_metadata_pr('offline-token', 'owner/repo')
    assert calls[-1] == ('ls-remote', '--exit-code', 'origin', 'refs/heads/sentinel-generated/run-123-1')
    assert not (tmp_path/'data/health/git_sync_state.json').exists()


@pytest.mark.parametrize('method,status,message,reason', [
    ('POST', 403, 'GitHub Actions is not permitted to create or approve pull requests.', 'ACTIONS_PR_CREATION_DISABLED'),
    ('POST', 403, 'Resource not accessible by integration', 'TOKEN_OR_POLICY_FORBIDDEN'),
    ('GET', 403, 'Forbidden', 'TOKEN_OR_POLICY_FORBIDDEN'),
    ('POST', 401, 'Bad credentials', 'TOKEN_AUTHENTICATION_REJECTED'),
    ('POST', 422, 'Validation failed', 'GITHUB_API_REJECTED'),
])
def test_pr_rejection_preserves_commit_evidence_and_only_owner_policy_can_continue(tmp_path, monkeypatch, method, status, message, reason):
    monkeypatch.setattr(git_sync, 'REPO_ROOT', tmp_path)
    monkeypatch.setenv('GITHUB_RUN_ID', '123')
    monkeypatch.setenv('GITHUB_RUN_ATTEMPT', '2')
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(tmp_path/'summary.md'))
    calls = []
    commit_sha = 'b'*40
    monkeypatch.setattr(git_sync, 'run_git', lambda *args: calls.append(args) or subprocess.CompletedProcess(args, 0, commit_sha))
    def urlopen(req, **kwargs):
        if req.method == method:
            body = json.dumps({'message': message, 'private_debug': 'offline-secret-token'}).encode()
            raise urllib.error.HTTPError(req.full_url, status, 'forbidden', {}, io.BytesIO(body))
        return Response([])
    monkeypatch.setattr(urllib.request, 'urlopen', urlopen)

    if reason == 'ACTIONS_PR_CREATION_DISABLED':
        result = git_sync.publish_metadata_pr('offline-secret-token', 'owner/repo')
        assert result['state'] == 'PERSISTED_REVIEW_BLOCKED'
        assert result['remote_verified'] is True
        assert result['review_required'] is True
        error_text = ''
    else:
        with pytest.raises(RuntimeError, match=reason) as error:
            git_sync.publish_metadata_pr('offline-secret-token', 'owner/repo')
        result = None
        error_text = str(error.value)

    state = json.loads((tmp_path/'data/health/git_sync_state.json').read_text())
    expected_state = 'PERSISTED_REVIEW_BLOCKED' if reason == 'ACTIONS_PR_CREATION_DISABLED' else 'PERSISTED_PR_BLOCKED'
    assert state['state'] == expected_state
    assert state['reason'] == reason
    assert state['commit_sha'] == commit_sha and state['http_status'] == status
    assert state['remote_verified'] is True
    assert state['main_updated'] is False and 'pr_number' not in state
    assert state['branch'] == 'sentinel-generated/run-123-2'
    assert state['compare_url'] == f'https://github.com/owner/repo/compare/main...{commit_sha}'
    assert calls == [
        ('rev-parse', 'HEAD'),
        ('push', 'origin', 'HEAD:refs/heads/sentinel-generated/run-123-2'),
        ('ls-remote', '--exit-code', 'origin', 'refs/heads/sentinel-generated/run-123-2'),
    ]
    evidence = (tmp_path/'summary.md').read_text() + json.dumps(state) + error_text
    assert 'offline-secret-token' not in evidence and 'private_debug' not in evidence
    assert 'main not updated' in evidence and 'do not bypass main protection' in evidence


@pytest.mark.parametrize('failure,reason', [
    ('transport', 'GITHUB_TRANSPORT_UNAVAILABLE'),
    ('json', 'INVALID_GITHUB_RESPONSE'),
    ('lookup', 'INVALID_PR_LOOKUP_RESPONSE'),
    ('identity', 'MISSING_PR_IDENTITY'),
])
def test_github_response_failure_never_claims_a_pr_exists(tmp_path, monkeypatch, failure, reason):
    monkeypatch.setattr(git_sync, 'REPO_ROOT', tmp_path)
    monkeypatch.setenv('GITHUB_RUN_ID', '123')
    monkeypatch.setenv('GITHUB_RUN_ATTEMPT', '1')
    monkeypatch.setattr(git_sync, 'run_git', lambda *args: subprocess.CompletedProcess(args, 0, 'c'*40))
    def urlopen(req, **kwargs):
        if failure == 'transport':
            raise urllib.error.URLError('offline-secret-token')
        if failure == 'json':
            class InvalidResponse(Response):
                def read(self, size): return b'not-json offline-secret-token'
            return InvalidResponse(None)
        if failure == 'lookup': return Response({'number': 701})
        return Response([] if req.method == 'GET' else {})
    monkeypatch.setattr(urllib.request, 'urlopen', urlopen)
    with pytest.raises(RuntimeError, match=reason) as error:
        git_sync.publish_metadata_pr('offline-secret-token', 'owner/repo')
    state = json.loads((tmp_path/'data/health/git_sync_state.json').read_text())
    assert state['state'] == 'PERSISTED_PR_BLOCKED' and state['reason'] == reason
    assert state['main_updated'] is False and 'pr_number' not in state
    assert 'offline-secret-token' not in str(error.value)

@pytest.fixture
def budget(monkeypatch):
    for name, value in [('_REQUESTS_USED', 0), ('_PROTOCOL_STARTED', None), ('_RETRY_NOT_BEFORE', 0.0)]:
        monkeypatch.setattr(convergence, name, value)
    ticks = [1000.0]
    monkeypatch.setattr(convergence.time, 'monotonic', lambda: ticks[0])
    monkeypatch.setattr(convergence.time, 'sleep', lambda seconds: ticks.__setitem__(0, ticks[0] + seconds))
    return ticks

def test_daily_rate_limit_stops_further_requests_without_claiming_delivery(monkeypatch, budget):
    calls = []
    def limited(req, **kwargs):
        calls.append(req.full_url)
        raise urllib.error.HTTPError(req.full_url, 429, 'limited', {'Retry-After': '86400'}, io.BytesIO())
    monkeypatch.setattr(convergence, '_platform_open', limited)
    first = convergence._http_probe('https://example.test/report')
    second = convergence._http_probe('https://example.test/another')
    assert first.status_code == 429 and not first.success
    assert second.error.startswith('NOT_PROBED') and not second.success
    assert len(calls) == 1

def test_retry_after_is_respected_without_disabling_security(monkeypatch, budget):
    calls = []
    def limited(req, **kwargs):
        calls.append(budget[0])
        raise urllib.error.HTTPError(req.full_url, 429, 'limited', {'Retry-After': '90'}, io.BytesIO())
    monkeypatch.setattr(convergence, '_platform_open', limited)
    convergence._http_probe('https://example.test/report')
    convergence._http_probe('https://example.test/report')
    assert calls == [1000.0, 1090.0]

def test_global_request_cap_includes_status_reads(monkeypatch, budget):
    for _ in range(convergence.MAX_TOTAL_REQUESTS): assert convergence._claim_request()
    monkeypatch.setattr(convergence, '_platform_open', lambda *a, **k: pytest.fail('budget must prevent network'))
    assert not convergence._http_probe('https://example.test/report').success
    assert convergence.query_publication_status('intel--0123456789abcdef') is None

def test_exhausted_time_budget_does_not_send_more_requests(monkeypatch, budget):
    assert convergence._claim_request()
    budget[0] += convergence.MAX_PROTOCOL_SECONDS
    assert not convergence._claim_request()

def test_final_retry_has_no_backoff(monkeypatch, budget):
    monkeypatch.setattr(convergence, 'MAX_RETRIES', 1)
    monkeypatch.setattr(convergence, '_http_probe', lambda url: convergence.ProbeResult(url=url, status_code=500, success=False, latency_ms=1, is_transient=True))
    monkeypatch.setattr(convergence, '_backoff_wait', lambda *a: pytest.fail('no backoff after final retry'))
    assert not convergence.phase2_cdn_readiness_probe([], {}).success
    assert not convergence.phase3_incremental_retry([], {'files': {'reports/2026/10/intel--0123456789abcdef.html': {}}}).success


def test_a_single_missing_report_cannot_pass_the_sample(monkeypatch, budget):
    urls = [f"https://example.test/reports/2026/10/intel--{i:024x}.html" for i in range(15)]
    monkeypatch.setattr(convergence, '_extract_report_urls', lambda *a: (urls, []))
    monkeypatch.setattr(convergence, 'MAX_RETRIES', 1)
    monkeypatch.setattr(convergence, '_is_expected_publication_rejection', lambda *a: False)
    monkeypatch.setattr(convergence, '_http_probe', lambda url: convergence.ProbeResult(
        url=url, status_code=404 if url == urls[0] else 200, latency_ms=1,
        success=url != urls[0], is_transient=False))
    assert not convergence.phase3_incremental_retry([], {}).success

def test_real_ci_git_flow_preserves_generated_content_without_touching_main(tmp_path, monkeypatch):
    def git(cwd, *args):
        return subprocess.run(['git', *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()
    bare = tmp_path/'origin.git'
    subprocess.run(['git', 'init', '--bare', '-q', str(bare)], check=True)
    root = tmp_path/'runner';root.mkdir()
    git(root, 'init', '-q', '-b', 'main')
    git(root, 'config', 'user.email', 'test@example.test')
    git(root, 'config', 'user.name', 'Offline test')
    (root/'index.html').write_text('<html>previous</html>')
    git(root, 'add', 'index.html');git(root, 'commit', '-q', '-m', 'seed')
    git(root, 'remote', 'add', 'origin', str(bare));git(root, 'push', '-u', 'origin', 'main')
    original = git(bare, 'rev-parse', 'refs/heads/main')
    (root/'index.html').write_text('<html>generated</html>')
    monkeypatch.setattr(git_sync, 'REPO_ROOT', root)
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.setenv('GH_TOKEN', 'offline-token')
    monkeypatch.setenv('GITHUB_REPOSITORY', 'owner/repo')
    monkeypatch.setenv('GITHUB_RUN_ID', '123')
    monkeypatch.setenv('GITHUB_RUN_ATTEMPT', '1')
    original_run = git_sync.run_git
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        if args[:2] == ('remote', 'set-url'):
            return subprocess.CompletedProcess(args, 0, '', '')  # Keep the isolated local origin.
        return original_run(*args, **kwargs)
    monkeypatch.setattr(git_sync, 'run_git', run)
    monkeypatch.setattr(urllib.request, 'urlopen', lambda req, **kw: Response([] if req.method == 'GET' else {'number': 701}))
    monkeypatch.chdir(root)
    git_sync.main()
    assert git(bare, 'rev-parse', 'refs/heads/main') == original
    assert git(bare, 'show', 'refs/heads/sentinel-generated/run-123-1:index.html') == '<html>generated</html>'
    assert not any(args[:3] == ('push', 'origin', 'main') for args in calls)
    assert json.loads((root/'data/health/git_sync_state.json').read_text())['main_updated'] is False

@pytest.mark.parametrize('use_uv', [False, True])
@pytest.mark.parametrize('fail_requirements', [False, True])
def test_dependency_install_bootstraps_core_and_rejects_partial_install(tmp_path, use_uv, fail_requirements):
    import os
    import yaml
    workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / '.github/workflows/sentinel-apex.yml').read_text())
    step = next(s for s in workflow['jobs']['generate-and-sync']['steps'] if s.get('name') == 'Install pipeline dependencies')
    assert step['timeout-minutes'] == 5
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    log = tmp_path / 'calls'
    # Use real bash and timeout; stub only package installers/import verification.
    stub = '#!/bin/bash\nprintf "%s\\n" "$*" >> "$INSTALL_LOG"\nif [[ "$*" == *"-r requirements.txt"* && "$FAIL_REQUIREMENTS" == "true" ]]; then exit 42; fi\n'
    for name in (['python', 'uv'] if use_uv else ['python']):
        p = bin_dir / name
        p.write_text(stub)
        p.chmod(0o755)
    for name, target in [('timeout', '/usr/bin/timeout')]:
        (bin_dir / name).symlink_to(target)
    (tmp_path / 'requirements.txt').write_text('offline fixture\n')
    env = dict(os.environ, PATH=str(bin_dir), INSTALL_LOG=str(log), FAIL_REQUIREMENTS=str(fail_requirements).lower())
    result = subprocess.run(['/bin/bash', '-e', '-c', step['run']], cwd=tmp_path, env=env, capture_output=True, text=True)
    calls = log.read_text().splitlines()
    assert 'PyYAML==6.0.1' in calls[0]
    assert '-r requirements.txt' in calls[1]
    assert 'urllib3<' not in '\n'.join(calls)
    assert result.returncode == (42 if fail_requirements else 0)
    assert len(calls) == (2 if fail_requirements else 3)
