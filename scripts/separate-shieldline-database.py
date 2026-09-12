#!/usr/bin/env python3
"""Explicit operator cutover. Does not delete source data or existing resources."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ROOT / 'docker/local'
OVERRIDE = COMPOSE / 'docker-compose.override.yml'
STATE = ROOT / '.local/shieldline-database-cutover.json'


def run(args, **kwargs):
    # Never include command arguments or database error text (potential PII) in errors.
    result = subprocess.run(args, cwd=COMPOSE, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed (exit {result.returncode}); stopped safely')
    return result


def output(args):
    return run(args, stdout=subprocess.PIPE).stdout.decode().strip()


def inspect(container):
    return json.loads(output(['docker', 'inspect', container]))[0]


def env(container):
    return dict(item.split('=', 1) for item in container['Config']['Env'] if '=' in item)


def private_json(path, data):
    with path.open('x') as stream:
        json.dump(data, stream, indent=2)


def sql(container, user, database, statement):
    return run(['docker', 'exec', '-i', container, 'psql', '-X', '-qAt',
                '-v', 'ON_ERROR_STOP=1', '-U', user, '-d', database],
               input=statement.encode(), stdout=subprocess.PIPE).stdout.decode().strip()


def identifier(value):
    return '"' + value.replace('"', '""') + '"'


def inventory(container, user, database):
    # Hash sorted row digests to compare complete data, without returning private rows.
    tables = sql(container, user, database,
                 "SELECT tablename FROM pg_tables WHERE schemaname='public' AND starts_with(tablename,'shieldline_') ORDER BY tablename;").splitlines()
    if not tables:
        raise RuntimeError('No Shieldline tables found')
    result = {}
    for table in tables:
        digest_rows = sql(container, user, database,
                          'SET statement_timeout=120000; SELECT md5(to_jsonb(t)::text) '
                          f'FROM public.{identifier(table)} t ORDER BY 1;')
        result[table] = {
            'rows': len(digest_rows.splitlines()) if digest_rows else 0,
            'digest': hashlib.sha256(digest_rows.encode()).hexdigest(),
        }
    sequences = sql(container, user, database,
                    "SELECT sequencename FROM pg_sequences WHERE schemaname='public' AND starts_with(sequencename,'shieldline_') ORDER BY sequencename;").splitlines()
    result['sequences'] = {name: sql(container, user, database,
                                   f'SELECT last_value,is_called FROM public.{identifier(name)};')
                           for name in sequences}
    return result


SERVICES = ['shieldline', 'shieldline-projection-worker', 'shieldline-notification-worker', 'shieldline-admin-bot-worker']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='Stop Shieldline, copy/verify data, then switch it')
    args = parser.parse_args()
    if not args.execute:
        parser.error('No changes made. Use --execute only for the planned Shieldline maintenance window.')
    def interrupted(_number, _frame):
        raise KeyboardInterrupt('Migration interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    os.umask(0o077)
    if os.environ.get('COMPOSE_FILE') or os.environ.get('COMPOSE_PROJECT_NAME'):
        raise RuntimeError('Custom Compose environment detected; review before cutover')
    if STATE.exists():
        raise RuntimeError('Existing cutover state found; inspect it instead of rerunning')
    for name in ['compose.yaml', 'compose.yml', 'compose.override.yaml', 'compose.override.yml',
                 'docker-compose.override.yaml']:
        if (COMPOSE / name).exists():
            raise RuntimeError(f'Existing {name}: manual merge required, no changes made')
    obriy_state = ROOT / '.local/obriy-database-cutover.json'
    if not obriy_state.exists() or json.loads(obriy_state.read_text()).get('phase') != 'complete':
        raise RuntimeError('Complete the Obriy migration first')
    original_override = OVERRIDE.read_bytes()
    previous = json.loads(original_override)
    if any(name in previous.get('services', {}) for name in SERVICES + ['shieldline-db']):
        raise RuntimeError('Existing Shieldline overrides require manual review')
    source_id = output(['docker', 'compose', 'ps', '-q', 'db'])
    app_id = output(['docker', 'compose', 'ps', '-q', 'shieldline'])
    source, app = inspect(source_id), inspect(app_id)
    if set(app['NetworkSettings']['Networks']) != {'kma-local_default'}:
        raise RuntimeError('Unexpected Shieldline networks; review before cutover')
    source_env, app_env = env(source), env(app)
    database, user = source_env['POSTGRES_DB'], source_env['POSTGRES_USER']
    if source['Config']['Labels'].get('com.docker.compose.project') != 'kma-local':
        raise RuntimeError('Unexpected source Compose project')
    if (app_env.get('SHIELDLINE_DB_HOST') != 'db' or app_env.get('SHIELDLINE_DB_NAME') != database
            or app_env.get('SHIELDLINE_DATABASE_URL')):
        raise RuntimeError('Unexpected current Shieldline database connection')
    effective = json.loads(output(['docker', 'compose', 'config', '--format', 'json']))
    if effective['services']['shieldline'].get('environment') != app_env:
        # Image-provided defaults are not present in Compose. Compare configured keys only.
        configured = effective['services']['shieldline'].get('environment', {})
        if any(str(value) != app_env.get(key) for key, value in configured.items()):
            raise RuntimeError('Running Shieldline environment differs from Compose; reconcile first')
    if app_env.get('SHIELDLINE_STORAGE_DRIVER') != 'postgres':
        raise RuntimeError('Shieldline is not configured for PostgreSQL')
    original_ids = {}
    original_envs = {}
    for service in SERVICES:
        cid = output(['docker', 'compose', 'ps', '-q', service])
        current = inspect(cid)
        values = env(current)
        writers = output(['docker', 'ps', '-q', '--filter', f'label=com.docker.compose.service={service}']).splitlines()
        if len(writers) != 1 or not cid.startswith(writers[0]):
            raise RuntimeError(f'Unexpected number of {service} writers')
        if (values.get('SHIELDLINE_DB_HOST') != 'db' or values.get('SHIELDLINE_DB_NAME') != database
                or set(current['NetworkSettings']['Networks']) != {'kma-local_default'}):
            raise RuntimeError(f'Unexpected connection/network: {service}')
        if any(str(value) != values.get(key) for key, value in effective['services'][service].get('environment', {}).items()):
            raise RuntimeError(f'Compose environment differs from running {service}')
        original_ids[service] = cid
        original_envs[service] = values
    for object_type, name in [('container', 'kma-local-shieldline-db-1'), ('volume', 'kma-local_shieldline_pg_data')]:
        if subprocess.run(['docker', object_type, 'inspect', name], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError(f'Target already exists: {name}; refusing to overwrite')
    for location in [ROOT, Path(output(['docker', 'info', '--format', '{{.DockerRootDir}}'])), Path('/var/lib/containerd')]:
        if location.exists():
            fs = os.statvfs(location)
            if fs.f_bavail * fs.f_frsize < 10 * 1024**3:
                raise RuntimeError('Need at least 10 GiB free on source and Docker filesystems')
    # Abort on incoming/outgoing cross-schema foreign keys.
    cross = sql(source_id, user, database, """
      SELECT count(*) FROM pg_constraint k
      JOIN pg_class a ON a.oid=k.conrelid JOIN pg_namespace an ON an.oid=a.relnamespace
      JOIN pg_class b ON b.oid=k.confrelid JOIN pg_namespace bn ON bn.oid=b.relnamespace
      WHERE k.contype='f' AND
      ((an.nspname='public' AND starts_with(a.relname,'shieldline_')) <>
       (bn.nspname='public' AND starts_with(b.relname,'shieldline_')));
    """)
    if cross != '0':
        raise RuntimeError('Cross-schema foreign keys found; no changes made')
    run_dir = ROOT / 'backups/db-cutover' / ('shieldline-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()))
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / 'original-override.json').write_bytes(original_override)
    STATE.parent.mkdir(exist_ok=True)
    admin_password, app_password = secrets.token_hex(32), secrets.token_hex(32)
    credential_dir = STATE.parent / 'shieldline-database-secrets'
    credential_dir.mkdir(exist_ok=False)
    credentials = credential_dir / '.env.database'
    with credentials.open('x') as stream:
        stream.write(f'POSTGRES_USER=shieldline_admin\nPOSTGRES_DB=shieldline\nPOSTGRES_PASSWORD={admin_password}\n')
    definition = {
        'name': 'kma-local',
        'services': {'shieldline-db': {
            'image': source['Image'], 'restart': 'unless-stopped',
            'env_file': [str(credentials)], 'mem_limit': '1g', 'cpus': 1.0, 'shm_size': '128m',
            'volumes': ['shieldline_pg_data:/var/lib/postgresql'], 'networks': ['shieldline_private'],
            'healthcheck': {'test': ['CMD-SHELL', 'pg_isready -h 127.0.0.1 -U shieldline_admin -d shieldline'],
                            'interval': '5s', 'timeout': '5s', 'retries': 24},
        }},
        'networks': {'shieldline_private': {'internal': True}},
        'volumes': {'shieldline_pg_data': {}},
    }
    stage = run_dir / 'database.compose.json'
    private_json(stage, definition)
    run(['docker', 'compose', '-f', str(stage), 'config', '--quiet'], stdout=subprocess.DEVNULL)
    state = {'phase': 'preparing', 'source_container': source_id, 'original_containers': original_ids,
             'run_dir': str(run_dir), 'target': 'kma-local-shieldline-db-1'}
    private_json(STATE, state)

    def phase(value):
        state['phase'] = value
        temporary = STATE.with_suffix('.tmp')
        temporary.write_text(json.dumps(state, indent=2))
        temporary.replace(STATE)
        print(value, flush=True)

    stopped_ids = []
    activated = False
    override_created = False
    try:
        run(['docker', 'compose', '-f', str(stage), 'up', '-d', 'shieldline-db'], stdout=subprocess.DEVNULL)
        target = 'kma-local-shieldline-db-1'
        for attempt in range(90):
            if inspect(target)['State'].get('Health', {}).get('Status') == 'healthy':
                break
            time.sleep(2)
        else:
            raise RuntimeError('New database not healthy')
        sql(target, 'shieldline_admin', 'shieldline',
            f"CREATE ROLE shieldline_app LOGIN PASSWORD '{app_password}' NOSUPERUSER NOCREATEDB NOCREATEROLE; "
            'ALTER DATABASE shieldline OWNER TO shieldline_app; REVOKE CONNECT ON DATABASE shieldline FROM PUBLIC; '
            'GRANT CONNECT ON DATABASE shieldline TO shieldline_app;')
        phase('stopping-source-writer')
        for cid in original_ids.values():
            stopped_ids.append(cid)
            run(['docker', 'stop', '--time', '60', cid], stdout=subprocess.DEVNULL)
            if inspect(cid)['State'].get('ExitCode') not in (0, 143):
                raise RuntimeError('A writer did not stop gracefully; inspect before retrying')
        phase('copying')
        baseline = inventory(source_id, user, database)
        with (run_dir / 'source.dump').open('xb') as dump:
            run(['docker', 'exec', source_id, 'pg_dump', '-Fc', '--table=public.shieldline_*',
                 '--lock-wait-timeout=10s', '--no-owner', '--no-acl', '-U', user, '-d', database], stdout=dump)
        with (run_dir / 'source.dump').open('rb') as dump:
            run(['docker', 'exec', '-i', target, 'pg_restore', '--exit-on-error', '--single-transaction',
                 '--no-owner', '--no-acl', '--role=shieldline_app', '-U', 'shieldline_admin', '-d', 'shieldline'],
                stdin=dump, stdout=subprocess.DEVNULL)
        phase('verifying')
        restored = inventory(target, 'shieldline_admin', 'shieldline')
        unchanged = inventory(source_id, user, database)
        if baseline != restored or baseline != unchanged:
            raise RuntimeError('Data mismatch or another writer changed source; cutover cancelled')
        private_json(run_dir / 'verified-inventory.json', restored)
        # A database login is tested over TCP, not a local trust-authenticated socket.
        run(['docker', 'exec', '-i', target, 'sh', '-c',
             'read -r PGPASSWORD; export PGPASSWORD; exec psql -h 127.0.0.1 -U shieldline_app -d shieldline -X -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM public.shieldline_users"'],
            input=(app_password + '\n').encode(), stdout=subprocess.DEVNULL)
        service_override = {
            'environment': {'SHIELDLINE_DB_HOST': 'shieldline-db', 'SHIELDLINE_DB_PORT': '5432',
                            'SHIELDLINE_DB_NAME': 'shieldline', 'SHIELDLINE_DB_USER': 'shieldline_app',
                            'SHIELDLINE_DB_PASSWORD': app_password},
            'networks': {'default': None, 'shieldline_private': None},
            'depends_on': {'shieldline-db': {'condition': 'service_healthy'}},
        }
        for service in SERVICES:
            definition['services'][service] = copy.deepcopy(service_override)
        # A migration restart must not discard queued Telegram updates.
        definition['services']['shieldline-admin-bot-worker']['environment']['SHIELDLINE_ADMIN_BOT_DROP_PENDING_UPDATES'] = 'false'
        combined = copy.deepcopy(previous)
        for section in ['services', 'networks', 'volumes']:
            for name, value in definition[section].items():
                if name in combined.setdefault(section, {}):
                    raise RuntimeError('Override name collision; no activation')
                combined[section][name] = value
        draft = run_dir / 'override.compose.json'
        private_json(draft, combined)
        merged = json.loads(output(['docker', 'compose', '-f', str(COMPOSE / 'docker-compose.yml'),
                                    '-f', str(draft), 'config', '--format', 'json']))
        for service_name, config in effective['services'].items():
            if service_name not in SERVICES and merged['services'].get(service_name) != config:
                raise RuntimeError('Compose merge changes an unrelated service; activation cancelled')
        for service in SERVICES:
            expected_env = dict(effective['services'][service]['environment'])
            expected_env.update(definition['services'][service]['environment'])
            if merged['services'][service]['environment'] != expected_env:
                raise RuntimeError('Unexpected merged worker environment; activation cancelled')
        if OVERRIDE.read_bytes() != original_override:
            raise RuntimeError('Override changed during migration; no activation')
        replacement = OVERRIDE.with_suffix('.cutover.tmp')
        private_json(replacement, combined)
        replacement.replace(OVERRIDE)
        override_created = True
        phase('activating-target-no-automatic-rollback')
        # Once this command begins, target writes may exist. Never resume stale source automatically.
        activated = True
        run(['docker', 'compose', 'up', '-d', '--no-deps', '--no-build', 'shieldline'], stdout=subprocess.DEVNULL)
        new_id = output(['docker', 'compose', 'ps', '-q', 'shieldline'])
        new_env = env(inspect(new_id))
        if new_env.get('SHIELDLINE_DB_HOST') != 'shieldline-db':
            raise RuntimeError('Connection verification failed')
        for attempt in range(90):
            probe = subprocess.run(['docker', 'exec', new_id, 'node', '-e',
                "fetch('http://127.0.0.1:8080/shieldline/api/health').then(async r=>process.exit(r.ok&&(await r.json()).storage==='postgres'?0:1)).catch(()=>process.exit(1))"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError('Shieldline readiness check failed')
        # Clear only migrated liveness markers so old source timestamps cannot pass readiness.
        sql(target, 'shieldline_admin', 'shieldline', 'DELETE FROM public.shieldline_worker_heartbeats;')
        run(['docker', 'compose', 'up', '-d', '--no-deps', '--no-build', *SERVICES[1:]], stdout=subprocess.DEVNULL)
        for service in SERVICES:
            cid = output(['docker', 'compose', 'ps', '-q', service])
            values = env(inspect(cid))
            expected = dict(original_envs[service])
            expected.update(definition['services'][service]['environment'])
            if any(values.get(key) != value for key, value in expected.items()):
                raise RuntimeError(f'Environment verification failed for {service}')
        expected_roles = 3 if original_envs['shieldline-admin-bot-worker'].get('SHIELDLINE_ADMIN_BOT_ENABLED', 'false').lower() == 'true' else 2
        for attempt in range(90):
            ready = sql(target, 'shieldline_admin', 'shieldline',
                        "SELECT count(DISTINCT role) FROM public.shieldline_worker_heartbeats WHERE role IN ('projection','notification','admin-bot') AND status='ready' AND updated_at>now()-interval '2 minutes';")
            if ready == str(expected_roles):
                break
            time.sleep(2)
        else:
            raise RuntimeError('Worker readiness verification failed')
        phase('complete')
        print('SHIELDLINE_DATABASE_SEPARATED_OK; source schema retained; target writes are now authoritative.')
    except (Exception, KeyboardInterrupt):
        if activated:
            subprocess.run(['docker', 'compose', 'stop', *SERVICES], cwd=COMPOSE,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            phase('attention-target-may-have-writes')
            print('Shieldline paused. Do NOT restart the old source: reconcile target writes first.', flush=True)
        else:
            if override_created:
                OVERRIDE.write_bytes(original_override)
            if stopped_ids:
                run(['docker', 'start', *stopped_ids], stdout=subprocess.DEVNULL)
            phase('failed-before-activation-source-retained')
        raise


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(str(error))
        raise SystemExit(1)
