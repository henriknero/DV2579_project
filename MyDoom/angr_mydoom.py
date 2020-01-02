#!/usr/bin/env python

import angr
import claripy
import os
import sys
import time
import argparse
import subprocess
import csv
import logging
#logging.getLogger('angr').setLevel('ERROR')

stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']

def debug_function(state):
    if state.addr < 0x1000000:
        print("Call to %s" % state)

path = "C:\\Users\\John\\DV2579_project\\MyDoom\\strip-girl-2.0bdcom_patches.exe"
argv_size = 2
find = 0x004a3de3
avoid = None

sym_argv = claripy.BVS('sym_argv', argv_size * 8)

p = angr.Project(path, auto_load_libs=False)

target = 0x004A3DB0
print('Generating CFGEmulated')
cfg = p.analyses.CFGEmulated(keep_state=True)

print('Generating CDG')
cdg = p.analyses.CDG(cfg)
print('Generating DDG')
ddg = p.analyses.DDG(cfg)

print('Finding node')
target_node = cfg.model.get_any_node(target, anyaddr=True)

back_slice = p.analyses.BackwardSlice(cfg, cdg, ddg, targets=[(target_node,-1)])
acfg = back_slice.annotated_cfg()
#p = angr.Project(path)
p.hook(0x004a465e, stub_func())
#p.hook(0x4a4285, stub_func())
state = p.factory.entry_state(args=[p.filename, sym_argv], add_options=angr.options.unicorn, veritesting=True)
state.inspect.b('call', action=debug_function)
simulation_manager = p.factory.simgr(state)
#simulation_manager.use_technique(angr.exploration_techniques.DFS())
simulation_manager.use_technique(angr.exploration_techniques.Slicecutor(acfg))
#logging.getLogger('angr').setLevel('DEBUG')
simulation_manager.explore(find=find, avoid=avoid)
#while simulation.found < 1:
#    sm.step()
for found in simulation_manager.found:
    print("dwHighDateTime")
    print(" ",found.solver.min(found.solver.constraints[42].args[0]))
    print("dwLowDateTime")
    print(" ",found.solver.min(found.regs.eax))
print("Testing")



#This takes long time but it can find the Logic bomb location.