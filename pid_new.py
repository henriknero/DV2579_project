#!/usr/bin/env python

import angr
import claripy
import time
import argparse
import logging

class new_getpid(angr.SimProcedure):
    def run(self):
        result = self.state.solver.BVS('pid', 32)
        return result

stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']

visited_list = []
backward_slice = {}

############################### Stuff to Change ######################################

path = "bin/pid_new"
# Target can be either a address or a function returning a Boolean
find = 0x004006bc

#interesting_function = 0x400590
interesting_state = 0x4006a5
interesting_value = claripy.BVS('regs.rax', 32)
use_simple_slicing = True
argv = []

######################################################################################

############################# Functions ##############################################
def not_in_path(state):
    if state.addr not in backward_slice:
        print("Avoiding block %#x" %state.addr)
        return True

def get_predecessors(node):
    for predecessor in node.predecessors:
        if predecessor.block_id not in visited_list:
            visited_list.append(predecessor.block_id)
            get_predecessors(predecessor)
        if predecessor.addr not in backward_slice:
            backward_slice[predecessor.addr] = []
        backward_slice[predecessor.addr].append(node.addr)

def debug_call(state):
    if state.addr < 0x1000000:
        print("Call to %s" % state)
#    if state.addr == interesting_function:
#        state.regs.rsi = interesting_value
def debug_exit(state):
    if state.addr == interesting_state:
        state.regs.rax = interesting_value
        print("Do something")

#######################################################################################
timer_start = time.time()
avoid = None
p = angr.Project(path)
p.hook_symbol('getpid', new_getpid())

if use_simple_slicing:
    print('Generating CFGEmulated')
    cfg = p.analyses.CFGEmulated(keep_state=True)
    target_node = cfg.model.get_any_node(find, anyaddr=True)
    cdg = None
    ddg = None
    backward_slice = p.analyses.BackwardSlice(cfg, cdg, ddg, targets=[(target_node, -1)], control_flow_slice=True).annotated_cfg()._exit_taken
    avoid=not_in_path
    backward_slice[find] = 0
    backward_slice[target_node.addr] = 0

state = p.factory.entry_state(args=[p.filename]+argv)

# SimInspect Functionality makes it possible to run functions or drop to shell when some
# specific events happen. They can be found at
# https://docs.angr.io/core-concepts/simulation#breakpoints
state.inspect.b('call', action=debug_call)
state.inspect.b('exit',when=angr.BP_AFTER, action=debug_exit)

simulation_manager = p.factory.simgr(state)
simulation_manager.explore(find=find, avoid=avoid)

for found in simulation_manager.found:
    print("Found state {}".format(hex(found.addr)))
    print(found.solver.eval(interesting_value, cast_to=int))

timer_end = time.time()
print("Time spent: {}".format(timer_end - timer_start))