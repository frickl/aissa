"""Run Lua contract tests when a system Lua 5.4 library is available."""
import ctypes
import ctypes.util
import json
from pathlib import Path
import unittest


class LuaScoringTests(unittest.TestCase):
    def test_async_scoring_contracts(self):
        library = ctypes.util.find_library('lua5.4')
        if not library:
            self.skipTest('Optional Lua 5.4 library not installed; run rspamadm configtest on server')
        lua = ctypes.CDLL(library)
        lua.luaL_newstate.restype = ctypes.c_void_p
        lua.luaL_openlibs.argtypes = [ctypes.c_void_p]
        lua.luaL_loadbufferx.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                       ctypes.c_char_p, ctypes.c_char_p]
        lua.lua_pcallk.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_int, ctypes.c_ssize_t, ctypes.c_void_p]
        lua.lua_tolstring.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        lua.lua_tolstring.restype = ctypes.c_char_p
        lua.lua_close.argtypes = [ctypes.c_void_p]
        root = Path(__file__).resolve().parent.parent
        source = ('AISSA_LUA_PATH=' + json.dumps(str(root / 'rspamd/aissa.lua')) + '\n'
                  + (root / 'tests/aissa_scoring_harness.lua').read_text()).encode()
        state = lua.luaL_newstate()
        self.assertTrue(state)
        try:
            lua.luaL_openlibs(state)
            code = lua.luaL_loadbufferx(state, source, len(source), b'scoring_tests', None)
            if not code:
                code = lua.lua_pcallk(state, 0, 0, 0, 0, None)
            self.assertEqual(code, 0, lua.lua_tolstring(state, -1, None))
        finally:
            lua.lua_close(state)
