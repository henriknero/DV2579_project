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
visited_list = []
backward_slice = {}
interesting_function = 0x400590
interesting_value = claripy.BVS('regs.rsi', 64)

def not_in_path(state):
    if state.addr not in backward_slice:
        print("Avoid block %#x found and avoided." %state.addr)
        return True
def get_predecessors(node):
    for predecessor in node.predecessors:
        if predecessor.block_id not in visited_list:
            visited_list.append(predecessor.block_id)
            get_predecessors(predecessor)
        if predecessor.addr not in backward_slice:
            backward_slice[predecessor.addr] = []
        backward_slice[predecessor.addr].append(node.addr)

def debug_function(state):
    if state.addr < 0x1000000:
        print("Call to %s" % state)
    if state.addr == interesting_function:
        state.regs.rsi = interesting_value
        print("Hmm")

path = "C:\\Users\\John\\DV2579_project\\MyDoom\\strip-girl-2.0bdcom_patches.exe"
argv_size = 3
avoid = None

sym_argv = claripy.BVS('sym_argv', argv_size * 8)

p = angr.Project(path, auto_load_libs=False)


target = 0x004a3de3
print('Generating CFGEmulated')
#logging.getLogger('angr.analyses').setLevel('DEBUG')
cfg = p.analyses.CFGEmulated(keep_state=True)
print("Done Generating CFG")
target_node = cfg.model.get_any_node(target, anyaddr=True)
get_predecessors(target_node)
backward_slice[target_node.addr] = 0
backward_slice[target] = 0


p = angr.Project(path, auto_load_libs=False)
state = p.factory.entry_state(args=[p.filename, sym_argv])
state.inspect.b('call', action=debug_function)
simulation_manager = p.factory.simgr(state)

simulation_manager.explore(find=target, avoid=not_in_path)
#while simulation.found < 1:
#    sm.step()
for found in simulation_manager.found:
    print(found.solver.eval(interesting_value, cast_to=int))
    print("Found something")



#This takes long time but it can find the Logic bomb location.