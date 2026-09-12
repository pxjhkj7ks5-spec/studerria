import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('cutover', Path(__file__).resolve().parents[1] / 'scripts/separate-shieldline-database.py')
cutover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cutover)


class ShieldlineCutoverTests(unittest.TestCase):
    def simulate(self, failure=None, admin=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compose = root / 'docker/local'
            compose.mkdir(parents=True)
            (root / '.local').mkdir()
            (root / '.local/obriy-database-cutover.json').write_text('{"phase":"complete"}')
            state = root / '.local/shieldline-database-cutover.json'
            override = compose / 'docker-compose.override.yml'
            previous = {'name': 'kma-local', 'services': {'obriy': {'environment': {'OBRIY_DB_HOST': 'obriy-db'}}, 'obriy-db': {'image': 'old'}}, 'networks': {'obriy_private': {'internal': True}}, 'volumes': {'obriy_pg_data': {}}}
            override.write_text(json.dumps(previous))
            calls = []
            common = {'SHIELDLINE_DB_HOST': 'db', 'SHIELDLINE_DB_NAME': 'student_portal', 'SHIELDLINE_STORAGE_DRIVER': 'postgres'}
            environments = {s: dict(common) for s in cutover.SERVICES}
            environments['shieldline-admin-bot-worker'].update({'SHIELDLINE_ADMIN_BOT_ENABLED': str(admin).lower(), 'SHIELDLINE_ADMIN_BOT_DROP_PENDING_UPDATES': 'true'})
            effective = {'services': dict(copy.deepcopy(previous['services']), **{s: {'environment': environments[s]} for s in cutover.SERVICES})}

            def inspected(name):
                if name == 'source':
                    return {'Image': 'sha256:known', 'Config': {'Env': ['POSTGRES_DB=student_portal', 'POSTGRES_USER=owner'], 'Labels': {'com.docker.compose.project': 'kma-local'}}}
                service = name.removeprefix('new-')
                if service in cutover.SERVICES:
                    values = dict(environments[service])
                    if name.startswith('new-'):
                        values.update(json.loads(override.read_text())['services'][service]['environment'])
                    return {'Config': {'Env': [f'{k}={v}' for k,v in values.items()]}, 'NetworkSettings': {'Networks': {'kma-local_default': {}}}, 'State': {'ExitCode': 0}}
                return {'State': {'Health': {'Status': 'healthy'}}}

            def output(args):
                if '--filter' in args: return args[-1].split('=')[-1]
                if args[-1] == 'db': return 'source'
                if args[-1] in cutover.SERVICES:
                    return ('new-' if 'shieldline' in json.loads(override.read_text())['services'] else '') + args[-1]
                if args[-1] == 'json':
                    result = copy.deepcopy(effective)
                    if '-f' in args:
                        draft = json.loads(next(Path(a) for a in args if a.endswith('override.compose.json')).read_text())
                        for s in cutover.SERVICES:
                            result['services'][s]['environment'].update(draft['services'][s]['environment'])
                        if failure == 'obriy-change': result['services']['obriy'] = {'changed': True}
                    return json.dumps(result)
                return str(root)

            def run(args, **kwargs):
                calls.append(args)
                if 'pg_dump' in args:
                    for s in cutover.SERVICES:
                        self.assertIn(['docker', 'stop', '--time', '60', s], calls)
                if 'pg_restore' in args and failure == 'restore': raise RuntimeError('restore failed')
                if '--no-build' in args and failure == 'activate': raise RuntimeError('activate failed')
                return SimpleNamespace(returncode=0, stdout=b'')

            def raw_run(args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=1 if 'inspect' in args else 0)

            def sql(*args):
                return str(3 if admin else 2) if 'count(DISTINCT role)' in args[-1] else '0'

            with patch.multiple(cutover, ROOT=root, COMPOSE=compose, OVERRIDE=override, STATE=state), \
                 patch.object(cutover, 'inspect', side_effect=inspected), patch.object(cutover, 'output', side_effect=output), \
                 patch.object(cutover, 'run', side_effect=run), patch.object(cutover, 'sql', side_effect=sql), \
                 patch.object(cutover, 'inventory', side_effect=[{'rows': 1}, {'rows': 2}, {'rows': 1}] if failure=='mismatch' else None, return_value={'rows': 1}), \
                 patch.object(cutover.subprocess, 'run', side_effect=raw_run), \
                 patch.object(cutover.os, 'statvfs', return_value=SimpleNamespace(f_bavail=100000000, f_frsize=4096)), \
                 patch.dict(cutover.os.environ, {}, clear=True), patch('sys.argv', ['script', '--execute']):
                if failure:
                    with self.assertRaises(RuntimeError): cutover.main()
                else: cutover.main()
            saved = json.loads(override.read_text())
            self.assertEqual(saved['services']['obriy'], previous['services']['obriy'])
            self.assertEqual(saved['services']['obriy-db'], previous['services']['obriy-db'])
            return json.loads(state.read_text()), calls, saved

    def test_success_preserves_obriy_and_switches_all_workers(self):
        for enabled in (False, True):
            state, calls, saved = self.simulate(admin=enabled)
            self.assertEqual(state['phase'], 'complete')
            for service in cutover.SERVICES:
                self.assertEqual(saved['services'][service]['environment']['SHIELDLINE_DB_HOST'], 'shieldline-db')
            self.assertEqual(saved['services']['shieldline-admin-bot-worker']['environment']['SHIELDLINE_ADMIN_BOT_DROP_PENDING_UPDATES'], 'false')

    def test_pre_activation_failures_restart_all_original_writers(self):
        for reason in ('restore', 'mismatch', 'obriy-change'):
            state, calls, saved = self.simulate(reason)
            self.assertEqual(state['phase'], 'failed-before-activation-source-retained')
            self.assertIn(['docker', 'start', *cutover.SERVICES], calls)
            self.assertNotIn('shieldline', saved['services'])

    def test_after_activation_stops_all_and_never_starts_old_writers(self):
        state, calls, _ = self.simulate('activate')
        self.assertEqual(state['phase'], 'attention-target-may-have-writes')
        self.assertIn(['docker', 'compose', 'stop', *cutover.SERVICES], calls)
        self.assertFalse(any(c[:2] == ['docker', 'start'] for c in calls))


if __name__ == '__main__': unittest.main()
