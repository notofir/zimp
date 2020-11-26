import importlib
import importlib.util
import marshal
import os.path
import sys
from zipfile import ZipFile

from Crypto.Cipher import AES


class ZimpLoader:
    def __init__(self, zimps):
        """

        :param zimps: {path_to_zimp: password}
        """
        self.zimps = zimps
        self.filenames = {}

    @staticmethod
    def _get_zimpname(path):
        return path.split(".")[0]

    def find_module(self, fullname, path=None):
        # Skip modules not in zimp file.
        if self._get_zimpname(fullname) in self.zimps.keys():
            return self

        return None

    def _get_code_obj(self, source, module):
        raise NotImplementedError("Use subclass")

    @staticmethod
    def _decrypt(data, key):
        if key is None:
            return data

        nonce, tag, encrypted_data = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        return cipher.decrypt_and_verify(encrypted_data, tag)

    @staticmethod
    def _find_path(file_names, path):
        if path in file_names:
            return path

        test_path = path + "c"
        if path in file_names:
            return test_path

        test_path = path + "/" + "__init__.py"
        if test_path in file_names:
            return test_path

        test_path = path + "/" + "__init__.pyc"
        if test_path in file_names:
            return test_path

    def _get_code(self, import_path):
        zimpname = os.path.basename(self._get_zimpname(import_path))
        zip_path = import_path.replace(".", "/")
        with ZipFile("{}.zip".format(zimpname), "r") as zimpfile:
            module_path = self._find_path(zimpfile.namelist(), zip_path)
            return module_path, self._decrypt(zimpfile.read(module_path), self.zimps[zimpname])

    def load_module(self, name):
        if name in sys.modules:
            return sys.modules[name]

        module_path, content = self._get_code(name)
        spec = importlib.util.spec_from_file_location(name, module_path)
        module = importlib.util.module_from_spec(spec)
        exec(self._get_code_obj(content, module), module.__dict__)
        sys.modules[name] = module
        return module


class PycZimpLoader(ZimpLoader):
    def __init__(self, zimps, marshal_offset):
        super().__init__(zimps)
        self.marshal_offset = marshal_offset

    def _get_code_obj(self, source, module):
        return marshal.loads(source[self.marshal_offset:])


class PyZimpLoader(ZimpLoader):
    def _get_code_obj(self, source, module):
        return compile(source, module.__spec__.origin, 'exec')


def register(importer):
    sys.meta_path.insert(-1, importer)
