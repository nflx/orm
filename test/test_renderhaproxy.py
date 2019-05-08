import unittest

from orm.render import ORMInternalRenderException
from orm.renderhaproxy import RenderHAProxy
import orm.renderhaproxy as renderhaproxy

class RenderHAProxyTest(unittest.TestCase):
    def assertIsStringList(self, lst, emptyOk=True):
        self.assertIsInstance(lst, list)
        for elem in lst:
            self.assertIsInstance(elem, str)
        if not emptyOk:
            self.assertTrue(lst)

    def setUp(self):
        self.render = RenderHAProxy(rule_docs={})

    def test_make_backend_action_origin_string(self):
        backend_config = {'origin': 'internet.example.com'}
        self.render.make_backend_action(backend_config, 'rule_id')
        self.assertIsStringList(self.render.backends, emptyOk=False)
        self.assertIsStringList(self.render.backend_acls, emptyOk=False)

    def test_make_backend_action_servers(self):
        backend_config = {'servers': ['space.example.com',
                                      {'server':'internet.example.com',
                                       'max_connections':10},
                                      {'server':'cats.example.com',
                                       'max_connections':10,
                                       'max_queued_connections':4}]}
        self.render.make_backend_action(backend_config, 'rule_id')
        self.assertIsStringList(self.render.backends, emptyOk=False)
        self.assertIsStringList(self.render.backend_acls, emptyOk=False)

    def test_make_backend_action_origins(self):
        backend_config = {'origins': ['space.example.com',
                                      {'origin':'internet.example.com'},
                                      {'server':'space.example.com',
                                       'max_connections':10},
                                      {'origin':'cats.example.com',
                                       'max_connections':10,
                                       'max_queued_connections':4}]}
        self.assertIsStringList(self.render.backends, emptyOk=False)
        self.assertIsStringList(self.render.backend_acls, emptyOk=False)

    def test_make_backend_action_server_string(self):
        backend_config = {'server': 'space.svt.se'}
        self.render.make_backend_action(backend_config, 'rule_id')
        self.assertIsStringList(self.render.backends, emptyOk=False)
        self.assertIsStringList(self.render.backend_acls, emptyOk=False)

    def test_make_backend_action_origins_string_invalid(self):
        backend_config = {'origins': 'space.svt.se'}
        self.render.make_backend_action(backend_config, 'rule_id')
        with self.assertRaises(ORMInternalRenderException):
            self.render.make_backend_action(backend_config, 'rule_id')

    def test_make_backend_action_servers_string_invalid(self):
        backend_config = {'servers': 'space.svt.se'}
        with self.assertRaises(ORMInternalRenderException):
            self.render.make_backend_action(backend_config, 'rule_id')

    def test_make_backend_action_invalid_string_invalid(self):
        backend_config = {'invalid': 'space.svt.se'}
        with self.assertRaises(ORMInternalRenderException):
            self.render.make_backend_action(backend_config, 'rule_id')

    def test_make_backend_action_server_server_object_invalid(self):
        backend_config = {'server': {'server':'space.svt.se',
                                     'max_connections':10}}
        with self.assertRaises(ORMInternalRenderException):
            self.render.make_backend_action(backend_config, 'rule_id')

    def test_make_backend_action_servers_origin_object_invalid(self):
        backend_config = {'servers': ['space.svt.se',
                                      {'origin':'internet.svt.se'}]}
        with self.assertRaises(ORMInternalRenderException):
            self.render.make_backend_action(backend_config, 'rule_id')

    def test_make_backend_action_servers_server_set_host_header_invalid(self):
        backend_config = {'servers': ['space.svt.se',
                                      {'server':'internet.svt.se',
                                       'set_host_header':'internet.svt.se'}]}
        with self.assertRaises(ORMInternalRenderException):
            self.render.make_backend_action(backend_config, 'rule_id')

    def test_make_backend_action_origins_server_invalid(self):
        backend_config = {'origins': {'server':'space.svt.se'}}
        with self.assertRaises(ORMInternalRenderException):
            self.render.make_backend_action(backend_config, 'rule_id')

    def test_make_backend_action_unknown(self):
        backend_config_unknown = {'unknown': 'backend config'}
        with self.assertRaises(ORMInternalRenderException):
            self.render.make_backend_action(backend_config_unknown, 'rule_id')

    def test_make_backend_action_unknown_scheme(self):
        backend_config_unknown_scheme = {'origin': 'derp://example.com'}
        with self.assertRaises(ORMInternalRenderException):
            self.render.make_backend_action(backend_config_unknown_scheme,
                                            'rule_id')

    def test_make_actions(self):
        unknown_action_config = {'unknown': 'action',
                                 'backend': {'origin': 'example.com'}}
        with self.assertRaises(ORMInternalRenderException):
            self.render.make_actions(unknown_action_config, 'rule_id')
        action_config = {
            'redirect': {'type': 'temporary',
                         'url': 'example.com'},
            'header_southbound': [{'remove': 'this'}],
            'backend': {'origin': 'example.com'},
            'header_northbound': [{'remove': 'that'}],
            'req_path': [{
                'replace': {
                    'from_exact': 'yeah',
                    'to': 'ooo',
                    'how': 'first_occurrence'
                }
            }]
        }
        self.render.make_actions(action_config, 'rule_id')
        self.assertIsStringList(self.render.backends, emptyOk=False)
        self.assertIsStringList(self.render.backend_acls, emptyOk=False)

    def test_make_custom_internal_healthcheck(self):
        healthcheck_config = None
        out = renderhaproxy.make_custom_internal_healthcheck(healthcheck_config)
        self.assertIsInstance(out, list)
        self.assertFalse(out)

        healthcheck_config = {
            'http': {
                'method': 'GET',
                'path': '/',
                'domain': 'example.com'
            }
        }
        out = renderhaproxy.make_custom_internal_healthcheck(healthcheck_config)
        self.assertIsStringList(out, emptyOk=False)
