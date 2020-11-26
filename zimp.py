import argparse
import marshal
import os
import py_compile
from importlib import import_module
from pathlib import Path
from zipfile import ZipFile, PyZipFile

from Crypto.Cipher import AES

from loaders import register, PycZimpLoader, PyZimpLoader


def get_key(path):
    if path is None:
        return None

    with open(path, "rb") as file:
        return file.read()


class ZimpCreator:
    def __init__(self, name, key, optimize, is_pyc):
        self.name = name
        self.key = key
        self.optimize = optimize
        self.is_pyc = is_pyc

    def walk_pyc(self):
        with PyZipFile(self.name + ".zip", 'w', optimize=self.optimize) as zimpfile:
            zimpfile.writepy(self.name)

    @staticmethod
    def _get_data(path):
        raise NotImplementedError("Use subclass")

    def _encrypt(self, data):
        if self.key is None:
            return data

        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        encrypted_data, tag = cipher.encrypt_and_digest(data)
        return b"".join((nonce, tag, encrypted_data))

    def run(self):
        with ZipFile(self.name + ".zip", 'w') as zimpfile:
            # Iterate over all the files in directory
            for folder_name, subfolders, filenames in os.walk(self.name):
                for filename in filenames:
                    file_path = os.path.join(folder_name, filename)
                    if filename.endswith(".py"):
                        zimpfile.writestr(file_path + "c", self._encrypt(self._get_data(file_path)))


class PyZimpCreator(ZimpCreator):
    @staticmethod
    def _get_data(path):
        with open(path, "rb") as file:
            return file.read()


class PycZimpCreator(ZimpCreator):
    def _get_data(self, path):
        pycpath = py_compile.compile(path, optimize=self.optimize)
        with open(pycpath, "rb") as pycfile:
            return pycfile.read()


class ZimpRunner:
    def __init__(self, name, key):
        self.name = name
        self.key = key

    def _get_loader(self):
        raise NotImplementedError("Use subclass")

    def run(self):
        register(self._get_loader())
        import_module(self.name)


class PyZimpRunner(ZimpRunner):
    def _get_loader(self):
        return PyZimpLoader({self.name: self.key})


class PycZimpRunner(ZimpRunner):
    def __init__(self, name, key, marshal_offset):
        super().__init__(name, key)
        self.marshal_offset = marshal_offset

    def _get_loader(self):
        return PycZimpLoader({self.name: self.key}, self.marshal_offset)


def find_marshal():
    py_name = "__test_marshal.py"
    pyc_name = py_name + "c"
    try:
        open(py_name, "wb").close()
        py_compile.compile(py_name, pyc_name)
        with open(pyc_name, "rb") as pycfile:
            pyc = pycfile.read()

        for i in range(Path(pyc_name).stat().st_size):
            try:
                exec(marshal.loads(pyc[i:]))

            # ValueError when marshal fails. TypeError when exec fails. For example, during testing,
            # on i=9 marshal.loads returns an int, which fails exec.
            except (ValueError, TypeError):
                pass

            else:
                return i

    finally:
        os.unlink(py_name)
        os.unlink(pyc_name)


def run_zimp(args):
    if args.pyc:
        PycZimpRunner(args.name, get_key(args.key_file), args.marshal_offset).run()

    else:
        PyZimpRunner(args.name, get_key(args.key_file)).run()


def create_zimp(args):
    if args.pyc:
        PycZimpCreator(args.name, get_key(args.key_file), args.optimize, args.pyc).run()

    else:
        PyZimpCreator(args.name, get_key(args.key_file), args.optimize, args.pyc).run()


def main():
    modes = {
        "run": run_zimp,
        "zip": create_zimp
    }
    argparser = argparse.ArgumentParser()
    argparser.add_argument("mode", choices=modes.keys())
    argparser.add_argument("--key-file")
    argparser.add_argument("--name", required=True)

    run_argparser = argparser.add_argument_group("run", "Run zimp")
    run_argparser.add_argument("--pyc", action="store_true")
    run_argparser.add_argument("--marshal-offset", default=16)

    zip_argparser = argparser.add_argument_group("zip", "Create zimp")
    zip_argparser.add_argument("--compression-level", default=None)
    zip_argparser.add_argument("--optimize", type=int, default=-1)

    args = argparser.parse_args()
    modes[args.mode](args)


if __name__ == "__main__":
    main()
