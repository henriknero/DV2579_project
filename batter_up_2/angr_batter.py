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
def gen_control_flow_slice(cfg, target_node):
    path = {}
    for predecessor in target_node.predecessors:
        path.update(gen_control_flow_slice(cfg, predecessor))
    path[hex(target_node.addr)] = target_node
    return path

def debug_function(state):
    if state.addr < 0x1000000:
        print("Call to %s" % state)

path = "batter_up_2/batter_up_2"
argv_size = 2
find = 0x08048638
avoid = None

sym_argv = claripy.BVS('sym_argv', argv_size * 8)

p = angr.Project(path, auto_load_libs=True)

target = 0x08048638
print('Generating CFGEmulated')
#logging.getLogger('angr.analyses').setLevel('DEBUG')
cfg = p.analyses.CFGEmulated(keep_state=True)
target_node = cfg.model.get_any_node(target, anyaddr=True)
bs = gen_control_flow_slice(cfg, target_node)

print('Generating CDG')
cdg = p.analyses.CDG(cfg)
print('Generating DDG')
ddg = p.analyses.DDG(cfg)

print('Finding node')

back_slice = p.analyses.BackwardSlice(cfg, cdg, ddg, targets=[(target_node,-2)], control_flow_slice=True)
acfg = back_slice.annotated_cfg()
#logging.getLogger('angr.exploration_techniques').setLevel('DEBUG')
state = p.factory.entry_state(args=[p.filename, sym_argv], veritesting=True)
state.inspect.b('call', action=debug_function)
simulation_manager = p.factory.simgr(state)
#simulation_manager.use_technique(angr.exploration_techniques.DFS())
simulation_manager.use_technique(angr.exploration_techniques.Slicecutor(acfg))
#logging.getLogger('angr').setLevel('DEBUG')
simulation_manager.explore(find=find, avoid=avoid)
#while simulation.found < 1:
#    sm.step()
for found in simulation_manager.deadended:
    print("dwHighDateTime")
    print(" ",found.solver.min(found.solver.constraints[42].args[0]))
    print("dwLowDateTime")
    print(" ",found.solver.min(found.regs.eax))
print("Testing")



#This takes long time but it can find the Logic bomb location.