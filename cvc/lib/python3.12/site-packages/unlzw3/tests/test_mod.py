import importlib.resources as pkgr

from unlzw3 import unlzw


def test_simple():

    with pkgr.as_file(pkgr.files(__package__).joinpath("hello.Z")) as fn:
        assert unlzw(fn) == b"He110\n"


def test_lipsum():
    """
    courtesy lipsum.com
    """

    with pkgr.as_file(pkgr.files(__package__).joinpath("lipsum.com.Z")) as fn:
        data = unlzw(fn)

        assert data == unlzw(fn.read_bytes())
        assert len(data) == 100172
