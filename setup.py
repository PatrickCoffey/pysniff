#!/usr/bin/python

from distutils.core import setup
import py2exe

options_py2exe = dict(optimize=2,
               dll_excludes=["POWRPROF.dll"])

setup(
    console=['capture.py'],
    version='0.0.1',
    author='Patrick Coffey',
    description='a packet sniffer that is filtered to certain IP',
    copyright='schlerp 2015',
    license='GPL v3',
    name='packetSniff',
    options = {"py2exe" : options_py2exe}
)