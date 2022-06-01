import unittest
import tracevis 
import sys


class TestArguments(unittest.TestCase):
    def test_help(self):
        from io import StringIO
        out,err = StringIO(), StringIO()          
        sys.stdout, sys.stderr = out, err 
        with self.assertRaises(SystemExit):
            tracevis.get_args(['-h'], auto_exit=True)
        self.assertIn(err.getvalue(), "usage:")
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_no_args(self):
        from io import StringIO
        out,err = StringIO(), StringIO()          
        sys.stdout, sys.stderr = out, err 
        with self.assertRaises(SystemExit):
            tracevis.get_args([], auto_exit=True)
        self.assertIn(err.getvalue(), "usage:")
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__


    def test_defaults(self):
        from io import StringIO
        out,err = StringIO(), StringIO()          
        sys.stdout, sys.stderr = out, err 
        args = tracevis.get_args([], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': False, 'packet_input_method': 'hex', 
                    'packet_data': None, 'dns': False, 'dnstcp': False, 'continue': False, 'maxttl': None, 
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False, 
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None, 
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new'}
        self.assertEqual(args, expected)
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_config_file(self):
        from io import StringIO
        import os, json 
        md = self.maxDiff
        self.maxDiff = None
        out,err = StringIO(), StringIO()          
        sys.stdout, sys.stderr = out, err 
        samples_dir = 'samples/'
        for file in os.listdir(samples_dir):
            args = tracevis.get_args(['--config-file', os.path.join(samples_dir, file)], auto_exit=False)
            with open(os.path.join(samples_dir, file), 'r') as f:
                expected = json.load(f)
                del args['config_file'] 
                self.assertEqual(args, expected)
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__
        self.maxDiff = md

    def test_dns_mode(self):
        from io import StringIO
        out,err = StringIO(), StringIO()          
        sys.stdout, sys.stderr = out, err 
        args = tracevis.get_args(['--dns'], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': False, 'packet_input_method': None, 
                    'packet_data': None, 'dns': True, 'dnstcp': False, 'continue': False, 'maxttl': None, 
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False, 
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None, 
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new'}
        self.assertEqual(args, expected)
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_packet_mode(self):
        from io import StringIO
        out,err = StringIO(), StringIO()          
        sys.stdout, sys.stderr = out, err 
        args = tracevis.get_args(['--packet'], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': True, 'packet_input_method': 'hex', 
                    'packet_data': None, 'dns': False, 'dnstcp': False, 'continue': False, 'maxttl': None, 
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False, 
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None, 
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new'}
        self.assertEqual(args, expected)
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_packet_input_types(self):
        from io import StringIO
        out,err = StringIO(), StringIO()          
        sys.stdout, sys.stderr = out, err 
        args = tracevis.get_args(['--packet', '--packet-input-method', 'hex'], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': True, 'packet_input_method': 'hex', 
                    'packet_data': None, 'dns': False, 'dnstcp': False, 'continue': False, 'maxttl': None, 
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False, 
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None, 
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new'}
        self.assertEqual(args, expected)

        args = tracevis.get_args(['--packet', '--packet-input-method', 'json'], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': True, 'packet_input_method': 'json', 
                    'packet_data': None, 'dns': False, 'dnstcp': False, 'continue': False, 'maxttl': None, 
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False, 
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None, 
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new'}
        self.assertEqual(args, expected)

        args = tracevis.get_args(['--packet', '--packet-input-method', 'interactive'], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': True, 'packet_input_method': 'interactive', 
                    'packet_data': None, 'dns': False, 'dnstcp': False, 'continue': False, 'maxttl': None, 
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False, 
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None, 
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new'}
        self.assertEqual(args, expected)

        args = tracevis.get_args(['--packet', '--packet-input-method', 'json', '--packet-data', 'b64:e30='], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': True, 'packet_input_method': 'json', 
                'packet_data': 'b64:e30=', 'dns': False, 'dnstcp': False, 'continue': False, 'maxttl': None, 
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False, 
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None, 
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new'}
        self.assertEqual(args, expected)
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__
        
