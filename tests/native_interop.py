"""Independent stdlib ZIP/TAR interop against a compiled DLL; synthetic files only."""
import ctypes, io, pathlib, sys, tarfile, tempfile, zipfile
lib=ctypes.CDLL(str(pathlib.Path(sys.argv[1]).resolve()))
for name in ('ak_test','ak_create_zip','ak_create_tar'):
    f=getattr(lib,name);f.restype=ctypes.c_int64;f.argtypes=[ctypes.c_char_p] if name=='ak_test' else [ctypes.c_char_p,ctypes.c_char_p]
lib.ak_extract.argtypes=[ctypes.c_char_p]*3;lib.ak_extract.restype=ctypes.c_int64
payload=bytes(range(256))*16
with tempfile.TemporaryDirectory(prefix='archivekit-interop-') as folder:
    root=pathlib.Path(folder)
    for method in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
        arc=root/f'python-{method}.zip'
        with zipfile.ZipFile(arc,'w',compression=method) as z:z.writestr('café/data.bin',payload)
        assert lib.ak_test(str(arc).encode())==1
        dest=root/f'extract-{method}'
        assert lib.ak_extract(str(arc).encode(),str(dest).encode(),None)==1
        assert (dest/'café/data.bin').read_bytes()==payload
    source=root/'source';source.mkdir();(source/'data.bin').write_bytes(payload)
    arc=root/'native.zip';assert lib.ak_create_zip(str(arc).encode(),str(source).encode())>0
    with zipfile.ZipFile(arc) as z:assert z.read('data.bin')==payload
    arc=root/'native.tar';assert lib.ak_create_tar(str(arc).encode(),str(source).encode())>0
    with tarfile.open(arc) as t:assert t.extractfile('data.bin').read()==payload
print('Native interop passed: Python ZIP store/deflate -> DLL; DLL ZIP/TAR -> Python')
