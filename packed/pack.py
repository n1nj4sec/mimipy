#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# mimipy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import sys
import os
import memorpy
import textwrap
import cPickle

def get_load_module_code(code, modulename):
    loader="""
import imp, sys
fullname={}
mod = imp.new_module(fullname)
mod.__file__ = "<bootloader>\\%s" % fullname
exec {} in mod.__dict__
sys.modules[fullname]=mod
    """.format(repr(modulename),repr(code))
    return loader

if __name__=="__main__":
    packed_script="""
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# mimipy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
# this is a self contained mimipy.py with all packages embedded
# last version available here https://github.com/n1nj4sec/mimipy
"""
    print "packing pupyimporter"
    with open("pupyimporter.py", 'rb') as f:
        code=f.read()
    packed_script+="\n"+get_load_module_code(code, "pupyimporter")+"\n"
    
    print "packing memorpy from %s"%memorpy.__path__[0]

    search_path=os.path.dirname(memorpy.__path__[0])
    modules_dic={}
    for root, dirs, files in os.walk(memorpy.__path__[0]):
        to_embedd = set()
        for f in files:
            base, ext = os.path.splitext(f)
            if base+'.pyc' in files and not ext in ('.pyc', '.pyo'):
                continue
            elif base+'.pyo' in files and not ext == '.pyo':
                continue
            else:
                to_embedd.add(f)

        for f in to_embedd:
            module_code=""
            with open(os.path.join(root,f),'rb') as fd:
                module_code=fd.read()
            modprefix = root[len(search_path.rstrip(os.sep))+1:]
            modpath = os.path.join(modprefix,f).replace("\\","/")
            modules_dic[modpath]=module_code
    packed_script+=textwrap.dedent("""
    import pupyimporter
    pupyimporter.install()
    pupyimporter.pupy_add_package(%s)
    """%repr(cPickle.dumps(modules_dic)))
    with open("../mimipy.py", 'rb') as f:
        packed_script+="\n"+f.read()
    with open("mimipy.py", "w") as w:
        w.write(packed_script)
    print "mimipy packed !"


