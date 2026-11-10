"""Adversarial Git configuration is inert data; no hostile subprocess runs here."""
import hashlib
import os
import subprocess
import sys
import zlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark import safe_git_observer as safe
from ci.gauntlet.benchmark import synthetic_developer_services as services
from ci.gauntlet.benchmark.contracts import digest


def metadata(tmp_path):
    checkout = tmp_path / 'candidate'
    repository = checkout / '.git'
    (repository / 'objects' / 'info').mkdir(parents=True)
    (repository / 'refs' / 'heads').mkdir(parents=True)
    (repository / 'HEAD').write_text('ref: refs/heads/main\n')
    (repository / 'refs' / 'heads' / 'main').write_text('a' * 40 + '\n')
    (repository / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = false\n')
    return checkout, repository


@pytest.mark.parametrize('configuration', [
    '[filter "candidate"]\nclean = CANDIDATE_COMMAND_MUST_NEVER_RUN\n',
    '[filter "candidate"]\nprocess = CANDIDATE_PROCESS_MUST_NEVER_RUN\n',
    '[include]\npath = /undeclared/operator-configuration\n',
    '[includeIf "gitdir:/candidate/"]\npath = /undeclared/conditional-config\n',
    '[core]\nfsmonitor = CANDIDATE_FSMONITOR_MUST_NEVER_RUN\n',
    '[core]\nworktree = /undeclared/operator-tree\n',
    '[core]\nsshCommand = CANDIDATE_SSH_MUST_NEVER_RUN\n',
])
def test_configuration_gate_never_launches_git_or_reads_include_target(tmp_path, monkeypatch, configuration):
    checkout, repository = metadata(tmp_path)
    (checkout / '.gitattributes').write_text('*.txt filter=candidate\n')
    (repository / 'config').write_text(configuration)
    reads = []
    original = safe._regular

    def read(path, **kwargs):
        reads.append(path)
        assert path.is_relative_to(tmp_path)
        return original(path, **kwargs)

    monkeypatch.setattr(safe, '_regular', read)
    monkeypatch.setattr(safe.subprocess, 'Popen', lambda *_a, **_k: pytest.fail('adversarial Git launched on host'))
    with pytest.raises(ValueError, match='unsupported'), safe.SafeGitObserver(checkout, custody_root=tmp_path):
        pytest.fail('unsafe configuration accepted')
    assert reads == [repository / 'config']


@pytest.mark.parametrize('name,content', [
    ('commondir', '/undeclared/operator-git\n'),
    ('gitdir', '/undeclared/operator-checkout\n'),
    ('shallow', 'a' * 40 + '\n'),
    ('objects/info/alternates', '/undeclared/operator-objects\n'),
    ('objects/info/http-alternates', 'https://undeclared.example.test/objects\n'),
])
def test_metadata_indirections_rejected_before_any_git_process(tmp_path, monkeypatch, name, content):
    checkout, repository = metadata(tmp_path)
    (repository / name).write_text(content)
    monkeypatch.setattr(safe.subprocess, 'Popen', lambda *_a, **_k: pytest.fail('redirected Git launched on host'))
    with pytest.raises(ValueError, match='unsupported'), safe.SafeGitObserver(checkout, custody_root=tmp_path):
        pytest.fail('metadata redirect accepted')


def test_only_private_raw_metadata_and_safe_command_argv_reach_subprocess(tmp_path, monkeypatch):
    checkout, repository = metadata(tmp_path)
    (repository / 'hooks').mkdir()
    (repository / 'hooks' / 'post-checkout').write_text('INERT HOST CANARY; NEVER EXECUTE\n')
    (repository / 'index').write_bytes(b'opaque candidate index, not interpreted')
    (repository / 'objects' / 'info' / 'attributes').write_text('*.txt filter=candidate\n')
    (checkout / '.gitattributes').write_text('*.txt filter=candidate\n')
    captures = []
    real_popen = subprocess.Popen

    def capture(command, **kwargs):
        captures.append((command, kwargs))
        private = Path(command[1].split('=', 1)[1])
        assert private != repository and not private.is_relative_to(tmp_path)
        assert kwargs['cwd'] == private
        assert not (private / 'index').exists()
        assert not (private / 'hooks').exists()
        assert not (private / 'objects' / 'info' / 'attributes').exists()
        config = (private / 'config').read_text()
        assert 'bare = true' in config and 'allow = never' in config and 'filter' not in config
        assert kwargs['env']['GIT_CONFIG_GLOBAL'] == kwargs['env']['GIT_CONFIG_SYSTEM'] == '/dev/null'
        assert 'safe.directory=*' not in command
        assert not any(arg.startswith('--work-tree') or arg == '-C' for arg in command)
        assert kwargs['stdin'] == subprocess.DEVNULL
        return real_popen(['/usr/bin/printf', '%s\n', 'a' * 40], **kwargs)

    monkeypatch.setattr(safe.subprocess, 'Popen', capture)
    with safe.SafeGitObserver(checkout, custody_root=tmp_path) as observer:
        private = observer.private
        assert observer.run('rev-parse', '--verify', 'HEAD') == b'a' * 40 + b'\n'
        for args in [('status', '--porcelain'), ('diff',), ('checkout', 'main'), ('hash-object', '--path=x', 'x')]:
            with pytest.raises(ValueError, match='raw object/ref'):
                observer.run(*args)
    assert len(captures) == 1 and not private.exists()


def test_literal_dirty_comparison_reads_bytes_not_filters_or_symlink_targets(tmp_path, monkeypatch):
    checkout, _repository = metadata(tmp_path)
    file = checkout / 'source.txt'
    file.write_bytes(b'inert expected source\n')
    monkeypatch.setattr(safe.subprocess, 'Popen', lambda *_a, **_k: pytest.fail('dirty comparison launched Git'))
    assert safe.raw_tracked_files_match(checkout, {'source.txt': ('100644', file.read_bytes())})
    file.write_bytes(b'changed raw source\n')
    assert not safe.raw_tracked_files_match(checkout, {'source.txt': ('100644', b'inert expected source\n')})
    link = checkout / 'literal-link'
    link.symlink_to('/undeclared/target-is-never-read')
    assert safe.raw_tracked_files_match(checkout, {'literal-link': ('120000', b'/undeclared/target-is-never-read')})
    (checkout / 'indirect').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match='indirect parent'):
        safe.raw_tracked_files_match(checkout, {'indirect/source.txt': ('100644', b'not read')})


def test_linked_worktree_observation_is_literal_owned_metadata_with_backlink(tmp_path, monkeypatch):
    checkout, repository = metadata(tmp_path)
    entry = repository / 'worktrees' / 'linked'
    entry.mkdir(parents=True)
    linked = tmp_path / 'linked'
    linked.mkdir()
    (linked / '.git').write_text('gitdir: ' + str(entry) + '\n')
    (entry / 'gitdir').write_text(str(linked / '.git') + '\n')
    (entry / 'commondir').write_text('../..\n')
    monkeypatch.setattr(safe.subprocess, 'Popen', lambda *_a, **_k: pytest.fail('worktree discovery launched Git'))
    with safe.SafeGitObserver(checkout, custody_root=tmp_path) as observer:
        assert observer.worktrees() == [str(linked)]
    (linked / '.git').write_text('gitdir: /undeclared/external-metadata\n')
    with safe.SafeGitObserver(checkout, custody_root=tmp_path) as observer, pytest.raises(ValueError, match='backlink'):
        observer.worktrees()


def test_service_never_reads_dependency_through_symlinked_parent(tmp_path, monkeypatch):
    # A minimal controller state with Git fully captured statically. No native
    # Git process or candidate command runs for this adversarial source layout.
    root = tmp_path / 'owned'
    root.mkdir()
    checkout = root / 'candidate'
    checkout.mkdir()
    outside = tmp_path / 'undelegated'
    (outside / 'event-tally').mkdir(parents=True)
    (checkout / 'node_modules').symlink_to(outside, target_is_directory=True)
    controller = object.__new__(services.SyntheticGitService)
    controller.root = root
    controller.key = Ed25519PrivateKey.generate()
    controller._changed = set()
    controller._db = root / 'controller.sqlite'
    import sqlite3
    with sqlite3.connect(controller._db) as connection:
        connection.execute('CREATE TABLE pulls(repository_id,head_branch,base,head_sha,state)')
    reads = []
    monkeypatch.setattr(controller, '_repository', lambda _id: {'checkout': checkout, 'remote': root / 'remote'})
    monkeypatch.setattr(controller, 'capture_effects', lambda: [])
    monkeypatch.setattr(controller, '_refs', lambda _id: {'refs/heads/main': 'a' * 40})
    monkeypatch.setattr(controller, '_raw_blobs', lambda *_args: ({}, {}, {}))

    def source_read(path):
        reads.append(path)
        assert path == checkout
        return digest({})

    class CapturedObserver:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def run(self, *_args):
            return b'a' * 40 + b'\n'

        def worktrees(self):
            return []

    monkeypatch.setattr(services, 'SafeGitObserver', CapturedObserver)
    monkeypatch.setattr(services, 'source_tree_digest', source_read)
    with pytest.raises(ValueError, match='indirect custody'):
        controller.freeze('run-repository', branch='main')
    assert reads == [checkout]


def test_compact_valid_git_dag_is_stopped_during_output_capture(tmp_path, monkeypatch):
    checkout, repository = metadata(tmp_path)

    def store(kind, content):
        raw = kind.encode() + b' ' + str(len(content)).encode() + b'\0' + content
        sha = hashlib.sha1(raw).hexdigest()
        destination = repository / 'objects' / sha[:2] / sha[2:]
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes(zlib.compress(raw))
        return sha

    blob = store('blob', b'inert\n')
    tree = store('tree', b'100644 leaf\0' + bytes.fromhex(blob))
    for _ in range(4):
        tree = store('tree', b''.join(b'40000 d' + str(i).encode() + b'\0' + bytes.fromhex(tree)
                                     for i in range(8)))
    commit = store('commit', ('tree ' + tree + '\nauthor Synthetic <synthetic@example.invalid> 1 +0000\n'
        'committer Synthetic <synthetic@example.invalid> 1 +0000\n\ninert\n').encode())
    (repository / 'refs/heads/main').write_text(commit + '\n')
    assert sum(p.stat().st_size for p in repository.rglob('*') if p.is_file()) < 4096
    with safe.SafeGitObserver(checkout, custody_root=tmp_path) as observer:
        observer.run('fsck', '--full', '--strict', '--no-reflogs')
        monkeypatch.setattr(safe, 'MAX_OUTPUT', 32768)
        reads, children = [], []
        real_read, real_popen = os.read, subprocess.Popen

        def read(fd, maximum):
            chunk = real_read(fd, maximum)
            reads.append(len(chunk))
            return chunk

        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        with monkeypatch.context() as patcher:
            patcher.setattr(safe.os, 'read', read)
            patcher.setattr(safe.subprocess, 'Popen', spawn)
            with pytest.raises(ValueError, match='output budget'):
                observer.run('ls-tree', '-rz', '--full-tree', commit)
        assert sum(reads) == safe.MAX_OUTPUT + 1
        assert len(children) == 1 and children[0].poll() is not None
        assert observer.run('rev-parse', 'HEAD') == (commit + '\n').encode()


@pytest.mark.parametrize('program,error', [
    ('import os; os.write(1,b"o"*24000); os.write(2,b"e"*24000)', ValueError),
    ('import time; time.sleep(10)', subprocess.TimeoutExpired),
])
def test_git_combined_stream_budget_and_deadline_reap_child(tmp_path, monkeypatch, program, error):
    checkout, _repository = metadata(tmp_path)
    real_popen, children = subprocess.Popen, []

    def spawn(_command, **kwargs):
        child = real_popen([sys.executable, '-I', '-S', '-c', program], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(safe, 'MAX_OUTPUT', 32768)
    monkeypatch.setattr(safe, 'COMMAND_TIMEOUT', 0.5)
    monkeypatch.setattr(safe.subprocess, 'Popen', spawn)
    with safe.SafeGitObserver(checkout, custody_root=tmp_path) as observer, pytest.raises(error):
        observer.run('rev-parse', 'HEAD')
    assert len(children) == 1 and children[0].poll() is not None
