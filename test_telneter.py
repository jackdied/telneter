from __future__ import print_function

import mock
import unittest
import telneter
import find_IACSE
from telneter import IAC, SB, SE, WILL, WONT, DO, DONT, STATUS


def multi_parse(data):
    parses = []
    while data:
        parses.append(telneter.parse(data))
        data = parses[-1][-1]
    return parses


class TelnetParser(unittest.TestCase):
    def test_IAC_escapes(self):
        IAC = telneter.IAC
        self.assertEqual(IAC+IAC, telneter.IAC_escape(IAC))
        self.assertEqual(IAC+IAC+IAC+IAC, telneter.IAC_escape(IAC+IAC))
        self.assertEqual('hello', telneter.IAC_escape('hello'))

        self.assertEqual(IAC+SB+STATUS+'hello'+IAC+SE,
                         telneter.construct_control(SB, STATUS, 'hello'))
        self.assertEqual(IAC+SB+STATUS+IAC+IAC+IAC+SE,
                         telneter.construct_control(SB, STATUS, IAC))

    def test_parse_plain(self):
        for line in ['xxxxx', 'yyyyy', 'xyz', 
                     '\0x\0y\0', '\nx\ny',  # nulls & newlines
                     '\xe2\x98\xaf \xe2\x98\xad \xe2\x9a\xa1',  # dat unicode
                    ]:
            self.assertEqual((None, line, b''), telneter.parse(line))

    def test_parse_control(self):
        self.assertEqual([((WILL, STATUS, b''), b'', b'')],
                         multi_parse(IAC+WILL+STATUS))
        self.assertEqual([(None, b'text', IAC+WILL+STATUS),
                          ((WILL, STATUS, b''), b'', b'')],
                         multi_parse(b'text' + IAC+WILL+STATUS))
        self.assertEqual([((WILL, STATUS, b''), b'', b'text'),
                          (None, b'text', b'')],
                         multi_parse(IAC+WILL+STATUS + b'text'))
        self.assertEqual([((WILL, STATUS, b''), b'', mock.ANY),
                          (None, b'text', mock.ANY),
                          ((DO, STATUS, b''), b'', b'')],
                         multi_parse(IAC+WILL+STATUS + 'text' + IAC+DO+STATUS))
        self.assertEqual([(None, 'before', mock.ANY),
                          ((WILL, STATUS, b''), b'', mock.ANY),
                          (None, 'after', b'')],
                         multi_parse(b'before' + IAC+WILL+STATUS + 'after'))

    def test_find_IACSE(self):
        for func in find_IACSE.all_finders:
            #print(func)
            self.assertEqual(-1, func(b''))
            self.assertEqual(0, func(IAC+SE))
            #                        ^^^^^^
            self.assertEqual(-1, func(IAC+IAC+SE))

            self.assertEqual(3, func(IAC+IAC+SE+IAC+SE))
            #                                   ^^^^^^
            self.assertEqual(2, func(IAC+IAC+IAC+SE))
            #                                ^^^^^^
            data = IAC+SB+STATUS+'xxx'+IAC+IAC+'xxx'+IAC+IAC + IAC+SE
            #                                                  ^^^^^^
            self.assertEqual(13, func(data))
            self.assertEqual(6, func(IAC+IAC+SE+'xxx'+IAC+SE))
            #                                         ^^^^^^
            self.assertEqual(9, func(IAC+IAC+SE+'xxx'+IAC+IAC+SE+IAC+SE))
            #                                                    ^^^^^^
            self.assertEqual(6, func(IAC+IAC+SE+'xxx'+IAC+SE+IAC+SE))
            #                                         ^^^^^^

    def _test_parse_sb(self):
        self.assertEqual([((SB, STATUS, 'payload'), b'', b'')],
                         multi_parse(IAC+SB+STATUS + 'payload' + IAC+SE))
        self.assertEqual([((SB, STATUS, 'payload'), b'', b'')],
                         multi_parse(IAC+SB+STATUS + 'payload'+IAC+IAC + IAC+SE))
        self.assertEqual([((SB, STATUS, 'pay'+IAC+'load'), b'', b'')],
                         multi_parse(IAC+SB+STATUS + 'pay'+IAC+IAC+'load' + IAC+SE))
        self.assertEqual([((SB, STATUS, 'pay'+IAC+SE+'load'), b'', b'')],
                         multi_parse(IAC+SB+STATUS + 'pay'+IAC+IAC+SE+'load' + IAC+SE))
        big_payload = 'x' * 1024 *1024
        self.assertEqual([((SB, STATUS, big_payload), b'', b'')],
                         multi_parse(IAC+SB+STATUS + big_payload + IAC+SE))
    
                
                
