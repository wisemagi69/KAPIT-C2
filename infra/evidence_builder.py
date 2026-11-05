"""PUBLIC_ONLY_OFFLINE_DEPENDENCY_RESOLVER. No installation/native readiness.

Default/import has no file/OS/daemon action. Only the authorized root operator
executes this fixed public metadata simulation. Never submit private input here.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re

from infra import evidence_container as commands

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT/'.cache/m1-runtime/private-scanner-build'
DOCKER = ROOT/'.cache/m1-runtime/container-tools/docker.exe'
IMAGE = 'docker.io/library/rust@sha256:4727898c104ecd2e22d780925832502faee9fe4e70581b8572af081370b315a0'
IMAGE_ID = 'sha256:4727898c104ecd2e22d780925832502faee9fe4e70581b8572af081370b315a0'
OCI_SOURCE = 'https://github.com/rust-lang/docker-rust'
SNAPSHOT = '20250723T000000Z'
KEYRING_SHA256 = '506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017'
INPUTS = {
    'debian-bookworm-20250723-InRelease': (151071, '919b6d130d8afa68a8680a24db6a09a9ccdc9226188b42079cd3a3d6fad028de', '/tmp/kapit-InRelease'),
    'debian-bookworm-20250723-Packages.xz': (8792976, 'c9bb33f1dc3e679fead4b8c53cac7a1ef99a26b06f48f56ba84510b9c4bc6625', '/tmp/kapit-Packages.xz'),
}
HELPERS = {
    'infra/evidence_container.py': '921f26e53ea67ebb066d534f682cef7fed215c708fed9426b14231e1b1043628',
    'infra/live_recovery_drill.py': 'cd6d9608399f0995b865da142611432b0c8a95ea1a9501b143dabebdc004388c',
    'infra/evidence_tools.py': 'b3d57248598364fabb208ea303a00139e27c5db1dc3746c95e32eda240f7202c',
}
REQUESTED = {'cmake': '3.25.1-1', 'libjson-c-dev': '0.16-2', 'libclang-dev': '1:14.0-55.7~deb12u1'}
MEMORY = 512*1024*1024
OWNER = 'kapit-public-offline-dependency-resolver-v1'
ID = re.compile(r'[0-9a-f]{64}\Z')
TOKEN = re.compile(r'[0-9a-f]{32}\Z')


class BuilderUnavailable(RuntimeError):
    def __init__(self, cleanup=False, container_id=None):
        self.code = 'BUILDER_CLEANUP_UNCONFIRMED' if cleanup else 'BUILDER_RESOLUTION_UNAVAILABLE'
        self.container_id = container_id if type(container_id) is str and ID.fullmatch(container_id) else None
        super().__init__(self.code)


def require(value):
    if not value:
        raise BuilderUnavailable()


def preparation():
    return {'schema': 1, 'status': 'PUBLIC_RESOLVER_NOT_EXECUTED', 'runtime_approval': False,
            'private_input_allowed': False, 'native_validation': 'DISABLED'}


def script():
    # No caller interpolation, downloads, installations, sources or execution flags.
    return '''umask 077
echo '506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017  /usr/share/keyrings/debian-archive-keyring.gpg' | sha256sum -c - >/dev/null
echo '919b6d130d8afa68a8680a24db6a09a9ccdc9226188b42079cd3a3d6fad028de  /tmp/kapit-InRelease' | sha256sum -c - >/dev/null
echo 'c9bb33f1dc3e679fead4b8c53cac7a1ef99a26b06f48f56ba84510b9c4bc6625  /tmp/kapit-Packages.xz' | sha256sum -c - >/dev/null
mkdir -p /tmp/kapit-repo/dists/bookworm/main/binary-amd64 /tmp/kapit-apt/empty /tmp/kapit-apt/lists/partial /tmp/kapit-apt/cache/archives/partial /tmp/kapit-apt/log
cp /tmp/kapit-InRelease /tmp/kapit-repo/dists/bookworm/InRelease
cp /tmp/kapit-Packages.xz /tmp/kapit-repo/dists/bookworm/main/binary-amd64/Packages.xz
printf '%s\\n' 'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] file:/tmp/kapit-repo bookworm main' > /tmp/kapit-apt/sources.list
cat > /tmp/kapit-apt/apt.conf <<'KAPIT_APT'
Dir::Etc::main "/dev/null";
Dir::Etc::parts "/tmp/kapit-apt/empty";
Dir::Etc::sourcelist "/tmp/kapit-apt/sources.list";
Dir::Etc::sourceparts "/tmp/kapit-apt/empty";
Dir::State::lists "/tmp/kapit-apt/lists";
Dir::State::status "/var/lib/dpkg/status";
Dir::Cache "/tmp/kapit-apt/cache";
Dir::Cache::archives "/tmp/kapit-apt/cache/archives";
Dir::Cache::pkgcache "/tmp/kapit-apt/cache/pkgcache.bin";
Dir::Cache::srcpkgcache "/tmp/kapit-apt/cache/srcpkgcache.bin";
Dir::Log "/tmp/kapit-apt/log";
Acquire::Check-Valid-Until "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AllowUnauthenticated "false";
Acquire::Languages "none";
Acquire::By-Hash "false";
Acquire::PDiffs "false";
Acquire::Retries "0";
APT::Architecture "amd64";
APT::Architectures { "amd64"; };
APT::Sandbox::User "root";
KAPIT_APT
export APT_CONFIG=/tmp/kapit-apt/apt.conf
KAPIT_STATUS_BEFORE=$(sha256sum /var/lib/dpkg/status | cut -d ' ' -f1)
dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\n' > /tmp/kapit-apt/inventory-before
LC_ALL=C sort /tmp/kapit-apt/inventory-before > /tmp/kapit-apt/inventory-before-sorted
KAPIT_INVENTORY_BEFORE=$(sha256sum /tmp/kapit-apt/inventory-before-sorted | cut -d ' ' -f1)
apt-get update >/dev/null
apt-get --simulate --no-install-recommends install cmake=3.25.1-1 libjson-c-dev=0.16-2 libclang-dev=1:14.0-55.7~deb12u1
test "$KAPIT_STATUS_BEFORE" = "$(sha256sum /var/lib/dpkg/status | cut -d ' ' -f1)"
dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\n' > /tmp/kapit-apt/inventory-after
LC_ALL=C sort /tmp/kapit-apt/inventory-after > /tmp/kapit-apt/inventory-after-sorted
test "$KAPIT_INVENTORY_BEFORE" = "$(sha256sum /tmp/kapit-apt/inventory-after-sorted | cut -d ' ' -f1)"
printf 'KAPIT_BASE_STATUS_SHA256 %s\\n' "$KAPIT_STATUS_BEFORE"
printf 'KAPIT_BASE_INVENTORY_SHA256 %s\\n' "$KAPIT_INVENTORY_BEFORE"
'''


def command():
    return ['-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=/tmp/kapit-apt', 'LANG=C', 'LC_ALL=C', '/bin/sh', '-ceu', script()]


@dataclass(frozen=True)
class ResolverPolicy:
    token: str

    def __post_init__(self):
        require(type(self.token) is str and TOKEN.fullmatch(self.token) is not None)

    @property
    def name(self): return 'kapit-public-resolver-'+self.token

    @property
    def labels(self):
        return {'org.opencontainers.image.source': OCI_SOURCE, 'org.kapit.owner': OWNER, 'org.kapit.reservation': self.token}


def create_args(policy):
    require(type(policy) is ResolverPolicy)
    args = ['container', 'create', '--pull', 'never', '--platform', 'linux/amd64', '--name', policy.name,
            '--user', '0:0', '--workdir', '/tmp', '--network', 'none', '--ipc', 'none', '--cgroupns', 'private',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true', '--memory', str(MEMORY),
            '--memory-swap', str(MEMORY), '--pids-limit', '16', '--cpus', '1', '--ulimit', 'cpu=120:120',
            '--ulimit', 'nofile=128:128', '--ulimit', 'core=0:0', '--log-driver', 'none', '--restart', 'no',
            '--no-healthcheck', '--entrypoint', '/usr/bin/env']
    for key, value in sorted(policy.labels.items()): args += ['--label', key+'='+value]
    return args + [IMAGE, *command()]


def verify_image(doc):
    require(type(doc) is dict and doc.get('Id') == IMAGE_ID and doc.get('Os') == 'linux' and doc.get('Architecture') == 'amd64')
    require(doc.get('RepoDigests') in ([IMAGE], ['rust@sha256:'+IMAGE_ID[7:]]))
    cfg = doc.get('Config'); require(type(cfg) is dict)
    require(cfg.get('Labels') == {'org.opencontainers.image.source': OCI_SOURCE})
    require(not cfg.get('Volumes') and not cfg.get('Healthcheck') and type(cfg.get('Env')) is list)
    require(all(type(value) is str and '=' in value and '\x00' not in value for value in cfg['Env']))
    require(len({value.split('=', 1)[0] for value in cfg['Env']}) == len(cfg['Env']))
    return cfg['Env']


def ownership(doc, policy, container_id):
    require(type(doc) is dict and doc.get('Id') == container_id and doc.get('Name') == '/'+policy.name
            and doc.get('Image') == IMAGE_ID and doc.get('Config', {}).get('Labels') == policy.labels)


def verify_inspection(doc, policy, container_id, environment, *, after=False):
    ownership(doc, policy, container_id)
    cfg, host, state = (doc.get(key) for key in ('Config', 'HostConfig', 'State'))
    require(all(type(value) is dict for value in (cfg, host, state)))
    require(cfg.get('Env') == environment and cfg.get('Entrypoint') == ['/usr/bin/env'] and cfg.get('Cmd') == command()
            and cfg.get('User') == '0:0' and cfg.get('WorkingDir') == '/tmp' and cfg.get('OpenStdin') is False
            and cfg.get('Tty') is False and not cfg.get('Volumes') and cfg.get('Healthcheck') == {'Test': ['NONE']})
    exact = {'ReadonlyRootfs': False, 'NetworkMode': 'none', 'IpcMode': 'none', 'PidMode': '', 'CgroupnsMode': 'private',
             'Privileged': False, 'Memory': MEMORY, 'MemorySwap': MEMORY, 'NanoCpus': 1000000000, 'PidsLimit': 16,
             'LogConfig': {'Type': 'none', 'Config': {}}, 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}}
    for key, value in exact.items(): require(type(host.get(key)) is type(value) and host[key] == value)
    require(host.get('CapDrop') == ['ALL'] and host.get('CapAdd') in (None, []) and host.get('SecurityOpt') == ['no-new-privileges=true'])
    for key in ('Binds', 'Mounts', 'Tmpfs', 'Devices', 'DeviceRequests', 'PortBindings', 'Links', 'VolumesFrom',
                'ExtraHosts', 'GroupAdd', 'Dns', 'DnsOptions', 'DnsSearch', 'StorageOpt', 'Sysctls'):
        require(not host.get(key))
    limits = host.get('Ulimits')
    require(type(limits) is list and all(type(row) is dict and set(row) == {'Name', 'Soft', 'Hard'}
            and type(row['Name']) is str and type(row['Soft']) is int and type(row['Hard']) is int for row in limits))
    require(type(limits) is list and sorted(limits, key=lambda x: x.get('Name', '')) == sorted([
        {'Name': 'cpu', 'Soft': 120, 'Hard': 120}, {'Name': 'nofile', 'Soft': 128, 'Hard': 128},
        {'Name': 'core', 'Soft': 0, 'Hard': 0}], key=lambda x: x['Name']))
    require(not doc.get('Mounts') and state.get('Running') is False and state.get('Paused') is False and state.get('Restarting') is False)
    require(type(state.get('Pid')) is int and state['Pid'] == 0)
    require(state.get('Status') == ('exited' if after else 'created'))
    if after: require(state.get('OOMKilled') is False and type(state.get('ExitCode')) is int and state['ExitCode'] == 0)


def parse_resolution(raw):
    try:
        require(type(raw) is bytes and 0 < len(raw) <= 1048576)
        text = raw.decode('ascii')
        rows, seen, baselines = [], set(), {}
        pattern = re.compile(r'Inst ([a-z0-9][a-z0-9+.-]*(?::amd64)?) (?:\[[^\]\r\n]{1,128}\] )?\(([0-9][A-Za-z0-9.+:~_-]{0,127}) [^\r\n]{1,512} \[(amd64|all)\]\)\Z')
        for line in text.splitlines():
            require(len(line) <= 1024 and not line.startswith('Remv'))
            if line.startswith('KAPIT_BASE_'):
                parts = line.split(' ')
                require(len(parts) == 2 and parts[0] in {'KAPIT_BASE_STATUS_SHA256', 'KAPIT_BASE_INVENTORY_SHA256'}
                        and parts[0] not in baselines and ID.fullmatch(parts[1]) is not None)
                baselines[parts[0]] = parts[1]
                continue
            if not line.startswith('Inst'): continue
            match = pattern.fullmatch(line); require(match is not None)
            name, version, arch = match.groups(); name = name.removesuffix(':amd64')
            require(name not in seen); seen.add(name)
            rows.append({'package': name, 'version': version, 'architecture': arch})
            require(len(rows) <= 256)
        found = {row['package']: row for row in rows}
        for name, version in REQUESTED.items(): require(found.get(name) == {'package': name, 'version': version, 'architecture': 'amd64'})
        require(set(baselines) == {'KAPIT_BASE_STATUS_SHA256', 'KAPIT_BASE_INVENTORY_SHA256'})
        return {'packages': sorted(rows, key=lambda row: (row['package'], row['architecture'])),
                'baseline_status_sha256': baselines['KAPIT_BASE_STATUS_SHA256'],
                'baseline_inventory_sha256': baselines['KAPIT_BASE_INVENTORY_SHA256']}
    except (UnicodeError, ValueError, TypeError):
        raise BuilderUnavailable() from None


class _Host:
    """Real root-only file/CLI adapter. Tests replace this entire boundary."""
    def __init__(self, policy): self.policy = policy; self.stack = ExitStack()

    def __enter__(self):
        from infra.evidence_tools import Windows, checked
        from infra.live_recovery_drill import PrivateDirectory
        try:
            require(os.name == 'nt')
            self.api, self.private = Windows(), PrivateDirectory()
            path = ROOT
            for part in ('', *STAGE.relative_to(ROOT).parts):
                if part: path /= part
                self.stack.enter_context(self.api.pin(checked(path), directory=True))
            self.stack.enter_context(self.private.pin(STAGE, private=True, directory=True))
            self.stage = checked(STAGE/('resolver-'+self.policy.token))
            require(not self.stage.exists())
            self.private.create(self.stage)
            self.stack.enter_context(self.private.pin(self.stage, private=True, directory=True))
            self._pin_digest(DOCKER, 43207600, '0d24d78cfc6262aefc82e175123d0f0d81d416882b12893002383168a8ca6935')
            for name, digest in HELPERS.items(): self._pin_digest(ROOT/name, (ROOT/name).stat().st_size, digest)
            for name, (size, digest, _) in INPUTS.items(): self._pin_digest(STAGE/name, size, digest)
            return self
        except BaseException:
            self.stack.close(); raise

    def _pin_digest(self, path, size, digest):
        stream = self.stack.enter_context(self.api.pin(path))
        h = hashlib.sha256(); count = 0
        while True:
            block = stream.read(65536)
            if not block: break
            count += len(block); require(count <= size); h.update(block)
        require(count == size and h.hexdigest() == digest)

    def save(self, name, document):
        require(name in ('ownership.json', 'result.json'))
        path = self.stage/name
        # Only fresh protected child content; never overwrite an old receipt.
        with path.open('xb'): pass
        self.api.protect(path)
        raw = commands.canonical(document); require(len(raw) <= 65536)
        with path.open('r+b') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        stream = self.stack.enter_context(self.api.pin(path, private=True))
        require(stream.read(65537) == raw)

    def call(self, *args, timeout=15):
        return commands._bounded_command([str(DOCKER), '--host', commands.ENDPOINT, *args], timeout=timeout, maximum=1048576)

    def __exit__(self, *args): self.stack.close()


def _execute(policy, host):
    container_id = None; attempted = False; result = None
    def call(*args, timeout=15): return host.call(*args, timeout=timeout)
    def document(*args):
        code, out, _, reason = call(*args); require(code == 0 and reason == 'EXIT')
        try: value = json.loads(out.decode('utf-8'))
        except (ValueError, UnicodeError): raise BuilderUnavailable() from None
        require(type(value) is list and len(value) == 1 and type(value[0]) is dict)
        return value[0]
    def absent(*filters):
        code, out, _, reason = call('container', 'ls', '--all', '--no-trunc', '--filter', *filters, '--format', '{{.ID}}')
        require(code == 0 and reason == 'EXIT' and not out.strip())
    environment = verify_image(document('image', 'inspect', IMAGE))
    absent('name=^/'+policy.name+'$')
    try:
        attempted = True
        code, out, _, reason = call(*create_args(policy))
        try: returned = out.decode('ascii').strip()
        except UnicodeError: raise BuilderUnavailable() from None
        if ID.fullmatch(returned):
            container_id = returned
            host.save('ownership.json', {'schema': 1, 'created_id': container_id, 'created_name': policy.name,
                      'image_id': IMAGE_ID, 'labels': policy.labels, 'scope': 'PUBLIC_ONLY_OFFLINE_DEPENDENCY_RESOLVER'})
        require(container_id is not None and code == 0 and reason == 'EXIT')
        verify_inspection(document('container', 'inspect', container_id), policy, container_id, environment)
        for name, (_, _, target) in INPUTS.items():
            code, _, _, reason = call('container', 'cp', str(STAGE/name), container_id+':'+target)
            require(code == 0 and reason == 'EXIT')
        code, out, _, reason = call('container', 'start', '--attach', container_id, timeout=60)
        require(type(code) is int and code == 0 and reason == 'EXIT')
        verify_inspection(document('container', 'inspect', container_id), policy, container_id, environment, after=True)
        resolved = parse_resolution(out)
        result = {'schema': 1, 'status': 'PUBLIC_OFFLINE_SIMULATION_COMPLETED', 'snapshot': SNAPSHOT,
                  'created_id': container_id, 'image_id': IMAGE_ID, **resolved,
                  'dependency_closure': 'RESOLUTION_ONLY_NOT_ACQUIRED_OR_INSTALLED', 'runtime_approval': False,
                  'private_input_allowed': False, 'native_validation': 'DISABLED'}
    finally:
        if attempted:
            try:
                if container_id is None:
                    absent('name=^/'+policy.name+'$')
                else:
                    value = document('container', 'inspect', container_id); ownership(value, policy, container_id)
                    if value.get('State', {}).get('Running') is True:
                        code, _, _, reason = call('container', 'kill', '--signal', 'KILL', container_id)
                        require(code == 0 and reason == 'EXIT')
                    value = document('container', 'inspect', container_id); ownership(value, policy, container_id)
                    state = value.get('State', {})
                    require(state.get('Running') is False and state.get('Restarting') is False
                            and type(state.get('Pid')) is int and state['Pid'] == 0)
                    code, _, _, reason = call('container', 'rm', container_id); require(code == 0 and reason == 'EXIT')
                    absent('id='+container_id)
            except BaseException:
                raise BuilderUnavailable(cleanup=True, container_id=container_id) from None
    require(result is not None)
    result['cleanup'] = 'OWNED_CONTAINER_ABSENT_VERIFIED'
    host.save('result.json', result)
    return result


def run(*, execute=False, reservation=None):
    if execute is False: return preparation()
    require(execute is True)
    policy = ResolverPolicy(reservation)
    try:
        with _Host(policy) as host: return _execute(policy, host)
    except (BuilderUnavailable, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise BuilderUnavailable() from None


if __name__ == '__main__':
    print(json.dumps(preparation(), sort_keys=True, separators=(',', ':')))
