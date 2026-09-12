import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('cutover', Path(__file__).resolve().parents[1] / 'scripts/separate-shieldline-database.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class RetryTests(unittest.TestCase):
    def test_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = root / 'backups/db-cutover/attempt'
            prior.mkdir(parents=True)
            (prior / 'original-override.json').write_bytes(b'{}')
            secrets = root / '.local/shieldline-database-secrets'
            secrets.mkdir(parents=True)
            values = ['POSTGRES_USER=shieldline_admin', 'POSTGRES_DB=shieldline', 'POSTGRES_PASSWORD=test']
            (secrets / '.env.database').write_text('\n'.join(values))
            state = dict(phase='failed-before-activation-source-retained', source_container='source', target='kma-local-shieldline-db-1', run_dir=str(prior))
            target = dict(Id='target', Image='image', Config=dict(Env=values, Labels={'com.docker.compose.service':'shieldline-db'}),
                State={'Running':True}, HostConfig={'PortBindings':{}}, NetworkSettings={'Networks':{'kma-local_shieldline_private':{}}},
                Mounts=[{'Name':'kma-local_shieldline_pg_data','Destination':'/var/lib/postgresql'}])
            with patch.object(m, 'ROOT', root), patch.object(m, 'STATE', root / '.local/state.json'), \
                 patch.object(m, 'inspect', side_effect=lambda name: {'Image':'image'} if name == 'source' else target), \
                 patch.object(m, 'output', return_value=json.dumps([{'Containers':{'target':{}}}])), \
                 patch.object(m, 'sql', return_value='0') as sql:
                m.validate_retry(state, 'source', b'{}')
                for phase in ['complete', 'attention-target-may-have-writes', 'copying']:
                    with self.assertRaises(RuntimeError): m.validate_retry(dict(state, phase=phase), 'source', b'{}')
                with self.assertRaises(RuntimeError): m.validate_retry(state, 'changed-source', b'{}')
                with self.assertRaises(RuntimeError): m.validate_retry(state, 'source', b'changed')
                sql.return_value = '1'
                with self.assertRaises(RuntimeError): m.validate_retry(state, 'source', b'{}')
                sql.side_effect = ['0', '1']
                with self.assertRaises(RuntimeError): m.validate_retry(state, 'source', b'{}')

if __name__ == '__main__': unittest.main()
