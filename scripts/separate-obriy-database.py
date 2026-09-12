#!/usr/bin/env python3
"""Explicit operator cutover. Does not delete source data or existing resources."""
import argparse
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
STATE = ROOT / '.local/obriy-database-cutover.json'


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
                 "SELECT tablename FROM pg_tables WHERE schemaname='obriy' ORDER BY tablename;").splitlines()
    if not tables:
        raise RuntimeError('No Obriy tables found')
    result = {}
    for table in tables:
        digest_rows = sql(container, user, database,
                          'SET statement_timeout=120000; SELECT md5(to_jsonb(t)::text) '
                          f'FROM obriy.{identifier(table)} t ORDER BY 1;')
        result[table] = {
            'rows': len(digest_rows.splitlines()) if digest_rows else 0,
            'digest': hashlib.sha256(digest_rows.encode()).hexdigest(),
        }
    sequences = sql(container, user, database,
                    "SELECT sequencename FROM pg_sequences WHERE schemaname='obriy' ORDER BY sequencename;").splitlines()
    result['sequences'] = {name: sql(container, user, database,
                                   f'SELECT last_value,is_called FROM obriy.{identifier(name)};')
                           for name in sequences}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='Stop Obriy, copy/verify data, then switch it')
    args = parser.parse_args()
    if not args.execute:
        parser.error('No changes made. Use --execute only for the planned Obriy maintenance window.')
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
                 'docker-compose.override.yaml', 'docker-compose.override.yml']:
        if (COMPOSE / name).exists():
            raise RuntimeError(f'Existing {name}: manual merge required, no changes made')
    source_id = output(['docker', 'compose', 'ps', '-q', 'db'])
    app_id = output(['docker', 'compose', 'ps', '-q', 'obriy'])
    source, app = inspect(source_id), inspect(app_id)
    if set(app['NetworkSettings']['Networks']) != {'kma-local_default'}:
        raise RuntimeError('Unexpected Obriy networks; review before cutover')
    source_env, app_env = env(source), env(app)
    database, user = source_env['POSTGRES_DB'], source_env['POSTGRES_USER']
    if source['Config']['Labels'].get('com.docker.compose.project') != 'kma-local':
        raise RuntimeError('Unexpected source Compose project')
    if (app_env.get('OBRIY_DB_HOST') != 'db' or app_env.get('OBRIY_DB_NAME') != database
            or app_env.get('OBRIY_DATABASE_URL')):
        raise RuntimeError('Unexpected current Obriy database connection')
    effective = json.loads(output(['docker', 'compose', 'config', '--format', 'json']))
    if effective['services']['obriy'].get('environment') != app_env:
        # Image-provided defaults are not present in Compose. Compare configured keys only.
        configured = effective['services']['obriy'].get('environment', {})
        if any(str(value) != app_env.get(key) for key, value in configured.items()):
            raise RuntimeError('Running Obriy environment differs from Compose; reconcile first')
    if not app_env.get('OBRIY_ENCRYPTION_KEY'):
        raise RuntimeError('Missing encryption key; no changes made')
    duplicate_writers = output(['docker', 'ps', '-q', '--filter', 'label=com.docker.compose.service=obriy']).splitlines()
    if len(duplicate_writers) != 1 or not app_id.startswith(duplicate_writers[0]):
        raise RuntimeError('Unexpected number of Obriy writers; no changes made')
    for object_type, name in [('container', 'kma-local-obriy-db-1'), ('volume', 'kma-local_obriy_pg_data')]:
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
      WHERE k.contype='f' AND ((an.nspname='obriy')<>(bn.nspname='obriy'));
    """)
    if cross != '0':
        raise RuntimeError('Cross-schema foreign keys found; no changes made')
    run_dir = ROOT / 'backups/db-cutover' / ('obriy-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()))
    run_dir.mkdir(parents=True, exist_ok=False)
    STATE.parent.mkdir(exist_ok=True)
    admin_password, app_password = secrets.token_hex(32), secrets.token_hex(32)
    credential_dir = STATE.parent / 'obriy-database-secrets'
    credential_dir.mkdir(exist_ok=False)
    credentials = credential_dir / '.env.database'
    with credentials.open('x') as stream:
        stream.write(f'POSTGRES_USER=obriy_admin\nPOSTGRES_DB=obriy\nPOSTGRES_PASSWORD={admin_password}\n')
    definition = {
        'name': 'kma-local',
        'services': {'obriy-db': {
            'image': source['Image'], 'restart': 'unless-stopped',
            'env_file': [str(credentials)], 'mem_limit': '1g', 'cpus': 1.0, 'shm_size': '128m',
            'volumes': ['obriy_pg_data:/var/lib/postgresql'], 'networks': ['obriy_private'],
            'healthcheck': {'test': ['CMD-SHELL', 'pg_isready -h 127.0.0.1 -U obriy_admin -d obriy'],
                            'interval': '5s', 'timeout': '5s', 'retries': 24},
        }},
        'networks': {'obriy_private': {'internal': True}},
        'volumes': {'obriy_pg_data': {}},
    }
    stage = run_dir / 'database.compose.json'
    private_json(stage, definition)
    run(['docker', 'compose', '-f', str(stage), 'config', '--quiet'], stdout=subprocess.DEVNULL)
    state = {'phase': 'preparing', 'source_container': source_id, 'original_app': app_id,
             'run_dir': str(run_dir), 'target': 'kma-local-obriy-db-1'}
    private_json(STATE, state)

    def phase(value):
        state['phase'] = value
        temporary = STATE.with_suffix('.tmp')
        temporary.write_text(json.dumps(state, indent=2))
        temporary.replace(STATE)
        print(value, flush=True)

    stopped = False
    activated = False
    override_created = False
    try:
        run(['docker', 'compose', '-f', str(stage), 'up', '-d', 'obriy-db'], stdout=subprocess.DEVNULL)
        target = 'kma-local-obriy-db-1'
        for attempt in range(90):
            if inspect(target)['State'].get('Health', {}).get('Status') == 'healthy':
                break
            time.sleep(2)
        else:
            raise RuntimeError('New database not healthy')
        sql(target, 'obriy_admin', 'obriy',
            f"CREATE ROLE obriy_app LOGIN PASSWORD '{app_password}' NOSUPERUSER NOCREATEDB NOCREATEROLE; "
            'ALTER DATABASE obriy OWNER TO obriy_app; REVOKE CONNECT ON DATABASE obriy FROM PUBLIC; '
            'GRANT CONNECT ON DATABASE obriy TO obriy_app;')
        phase('stopping-source-writer')
        run(['docker', 'stop', '--time', '60', app_id], stdout=subprocess.DEVNULL)
        stopped = True
        phase('copying')
        baseline = inventory(source_id, user, database)
        with (run_dir / 'source.dump').open('xb') as dump:
            run(['docker', 'exec', source_id, 'pg_dump', '-Fc', '--schema=obriy',
                 '--lock-wait-timeout=10s', '--no-owner', '--no-acl', '-U', user, '-d', database], stdout=dump)
        with (run_dir / 'source.dump').open('rb') as dump:
            run(['docker', 'exec', '-i', target, 'pg_restore', '--exit-on-error', '--single-transaction',
                 '--no-owner', '--no-acl', '--role=obriy_app', '-U', 'obriy_admin', '-d', 'obriy'],
                stdin=dump, stdout=subprocess.DEVNULL)
        phase('verifying')
        restored = inventory(target, 'obriy_admin', 'obriy')
        unchanged = inventory(source_id, user, database)
        if baseline != restored or baseline != unchanged:
            raise RuntimeError('Data mismatch or another writer changed source; cutover cancelled')
        private_json(run_dir / 'verified-inventory.json', restored)
        # A database login is tested over TCP, not a local trust-authenticated socket.
        run(['docker', 'exec', '-i', target, 'sh', '-c',
             'read -r PGPASSWORD; export PGPASSWORD; exec psql -h 127.0.0.1 -U obriy_app -d obriy -X -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM obriy.schema_migrations"'],
            input=(app_password + '\n').encode(), stdout=subprocess.DEVNULL)
        definition['services']['obriy'] = {
            'environment': {'OBRIY_DB_HOST': 'obriy-db', 'OBRIY_DB_PORT': '5432',
                            'OBRIY_DB_NAME': 'obriy', 'OBRIY_DB_USER': 'obriy_app',
                            'OBRIY_DB_PASSWORD': app_password},
            'networks': {'default': None, 'obriy_private': None},
            'depends_on': {'obriy-db': {'condition': 'service_healthy'}},
        }
        draft = run_dir / 'override.compose.json'
        private_json(draft, definition)
        merged = json.loads(output(['docker', 'compose', '-f', str(COMPOSE / 'docker-compose.yml'),
                                    '-f', str(draft), 'config', '--format', 'json']))
        for service_name, config in effective['services'].items():
            if service_name != 'obriy' and merged['services'].get(service_name) != config:
                raise RuntimeError('Compose merge changes an unrelated service; activation cancelled')
        expected_env = dict(effective['services']['obriy']['environment'])
        expected_env.update(definition['services']['obriy']['environment'])
        if merged['services']['obriy']['environment'] != expected_env:
            raise RuntimeError('Unexpected merged Obriy environment; activation cancelled')
        private_json(OVERRIDE, definition)
        override_created = True
        phase('activating-target-no-automatic-rollback')
        # Once this command begins, target writes may exist. Never resume stale source automatically.
        activated = True
        run(['docker', 'compose', 'up', '-d', '--no-deps', '--no-build', 'obriy'], stdout=subprocess.DEVNULL)
        new_id = output(['docker', 'compose', 'ps', '-q', 'obriy'])
        new_env = env(inspect(new_id))
        if new_env.get('OBRIY_DB_HOST') != 'obriy-db' or new_env.get('OBRIY_ENCRYPTION_KEY') != app_env['OBRIY_ENCRYPTION_KEY']:
            raise RuntimeError('Connection/encryption verification failed')
        for attempt in range(90):
            probe = subprocess.run(['docker', 'exec', new_id, 'node', '-e',
                "fetch('http://127.0.0.1:8080/obriy/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError('Obriy readiness check failed')
        phase('complete')
        print('OBRIY_DATABASE_SEPARATED_OK; source schema retained; target writes are now authoritative.')
    except (Exception, KeyboardInterrupt):
        if activated:
            subprocess.run(['docker', 'compose', 'stop', 'obriy'], cwd=COMPOSE,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            phase('attention-target-may-have-writes')
            print('Obriy paused. Do NOT restart the old source: reconcile target writes first.', flush=True)
        else:
            if override_created:
                OVERRIDE.unlink()
            if stopped:
                run(['docker', 'start', app_id], stdout=subprocess.DEVNULL)
            phase('failed-before-activation-source-retained')
        raise


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(str(error))
        raise SystemExit(1)
