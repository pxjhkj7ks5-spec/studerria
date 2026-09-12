import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('cutover', Path(__file__).resolve().parents[1] / 'scripts/separate-obriy-database.py')
cutover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cutover)


class CutoverTests(unittest.TestCase):
    def simulate(self, failure=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compose = root / 'docker/local'
            compose.mkdir(parents=True)
            state = root / '.local/obriy-database-cutover.json'
            calls = []
            app_env = {'OBRIY_DB_HOST': 'db', 'OBRIY_DB_NAME': 'student_portal', 'OBRIY_ENCRYPTION_KEY': 'secret'}

            def inspected(name):
                if name == 'source':
                    return {'Image': 'sha256:known', 'Config': {'Env': ['POSTGRES_DB=student_portal', 'POSTGRES_USER=owner'], 'Labels': {'com.docker.compose.project': 'kma-local'}}}
                if name in ['app', 'new-app']:
                    values = dict(app_env)
                    if name == 'new-app':
                        values['OBRIY_DB_HOST'] = 'obriy-db'
                    return {'Config': {'Env': [f'{key}={value}' for key, value in values.items()]}, 'NetworkSettings': {'Networks': {'kma-local_default': {}}}}
                return {'State': {'Health': {'Status': 'healthy'}}}

            def output(args):
                if '--filter' in args: return 'app'
                if args[-1] == 'db': return 'source'
                if args[-1] == 'obriy': return 'app' if not (compose / 'docker-compose.override.yml').exists() else 'new-app'
                if '--format' in args and args[-1] == 'json':
                    if '-f' in args:
                        draft_path = next(Path(arg) for arg in args if arg.endswith('override.compose.json'))
                        draft = cutover.json.loads(draft_path.read_text())
                        combined_env = dict(app_env)
                        combined_env.update(draft['services']['obriy']['environment'])
                        return cutover.json.dumps({'services': {'obriy': {'environment': combined_env}}})
                    return cutover.json.dumps({'services': {'obriy': {'environment': app_env}}})
                return str(root)

            def run(args, **kwargs):
                calls.append(args)
                if 'pg_restore' in args and failure == 'restore':
                    raise RuntimeError('restore failed')
                if '--no-build' in args and failure == 'activate':
                    raise RuntimeError('activation failed')
                return SimpleNamespace(returncode=0, stdout=b'')

            def raw_run(args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=1 if 'inspect' in args else 0)

            with patch.multiple(cutover, ROOT=root, COMPOSE=compose, OVERRIDE=compose / 'docker-compose.override.yml', STATE=state), \
                 patch.object(cutover, 'inspect', side_effect=inspected), \
                 patch.object(cutover, 'output', side_effect=output), \
                 patch.object(cutover, 'run', side_effect=run), \
                 patch.object(cutover, 'sql', return_value='0'), \
                 patch.object(cutover, 'inventory', side_effect=[{'rows': 2}, {'rows': 3}, {'rows': 2}] if failure == 'mismatch' else None,
                              return_value={'users': {'rows': 2, 'digest': 'same'}}), \
                 patch.object(cutover.subprocess, 'run', side_effect=raw_run), \
                 patch.object(cutover.os, 'statvfs', return_value=SimpleNamespace(f_bavail=100000000, f_frsize=4096)), \
                 patch.dict(cutover.os.environ, {}, clear=True), \
                 patch('sys.argv', ['script', '--execute']):
                if failure:
                    with self.assertRaises(RuntimeError): cutover.main()
                else:
                    cutover.main()
            return cutover.json.loads(state.read_text()), calls, (compose / 'docker-compose.override.yml').exists()

    def test_success_keeps_override_and_marks_complete(self):
        state, calls, override = self.simulate()
        self.assertEqual(state['phase'], 'complete')
        self.assertTrue(override)
        self.assertFalse(any('start' in call and 'app' in call for call in calls))

    def test_restore_failure_resumes_source_without_switch(self):
        state, calls, override = self.simulate('restore')
        self.assertEqual(state['phase'], 'failed-before-activation-source-retained')
        self.assertIn(['docker', 'start', 'app'], calls)
        self.assertFalse(override)

    def test_activation_failure_never_resumes_stale_source(self):
        state, calls, override = self.simulate('activate')
        self.assertEqual(state['phase'], 'attention-target-may-have-writes')
        self.assertNotIn(['docker', 'start', 'app'], calls)
        self.assertIn(['docker', 'compose', 'stop', 'obriy'], calls)
        self.assertTrue(override)

    def test_data_mismatch_prevents_activation(self):
        state, calls, override = self.simulate('mismatch')
        self.assertEqual(state['phase'], 'failed-before-activation-source-retained')
        self.assertIn(['docker', 'start', 'app'], calls)
        self.assertFalse(any('--no-build' in call for call in calls))
        self.assertFalse(override)


if __name__ == '__main__':
    unittest.main()
