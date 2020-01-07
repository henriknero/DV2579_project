#!/usr/bin/env python

import angr
import claripy
import time
import argparse
import logging

# SimProcedures can be used to hook functioncalls and addresses to change the behaviour of the program or to optimize slow functions by writing them in python.
# https://docs.angr.io/extending-angr/simprocedures
class new_getpid(angr.SimProcedure):
    def run(self):
        result = self.state.solver.BVS('pid', 32)
        return result

# Angr comes with a bunch of stub-precedures, for example there is a Nop stub to just skip an instruction or function.
stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']

visited_list = []
backward_slice = {}

############################### Stuff to Change ######################################

path = "bin/time_test"
# Target can be either a address or a function returning a Boolean
find = 0x00400747

# By setting stdout to a value you can make angr search for a string instead of an address. I simply set the find variable to the function is_successful further down in this template.
stdout = b''

# These three variables are connected to the inspect functions debug_call and debug_exit.
interesting_function = None     # 0x400590 
interesting_state = None        # 0x400575
interesting_value = None        # claripy.BVS('regs.rax', 64)

# Utilizes angr.analysis.Backwardslice and angr.analysis.CFG to build a backwardslice of the program removing uninteresting branches
use_simple_slicing = True      

argv1_size = 11
argv2_size = 6
argv = []                       # [claripy.BVS('sym_argv', argv1_size * 8), claripy.BVS('sym_argv', argv2_size * 8)]
# Depending on how you want angr to work it is possible to add and remove different 
# options, these options can be found at:
#   https://github.com/angr/angr-doc/blob/master/docs/appendices/options.md
added_options = set()
#added_options.add(angr.options.STRICT_PAGE_ACCESS)
#added_options.add(angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)

removed_options = set()
#removed_options.add(angr.options.LAZY_SOLVES)
#removed_options.add(angr.options.EFFICIENT_STATE_MERGING)
######################################################################################

############################# Functions ##############################################
def not_in_path(state):
    if state.addr not in backward_slice:
        print("Avoiding block %#x" %state.addr)
        return True

def debug_call(state):
    if state.addr < 0x1000000:
        print("Call to %s" % state)
    if state.addr == interesting_function:
        state.regs.rsi = interesting_value
def debug_exit(state):
    if state.addr == interesting_state:
        state.regs.edx = interesting_value
        print("Do something")
def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return stdout in stdout_output

#######################################################################################
timer_start = time.time()
avoid = None
p = angr.Project(path)

# It is possible to hook both functions and addresses using the built in hooking functionality 
p.hook_symbol('getpid', new_getpid())
#p.hook(0x4006b0, debug_exit)

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

state = p.factory.entry_state(args=[p.filename]+argv, add_options=added_options, remove_options=removed_options)

# SimInspect Functionality makes it possible to run functions or drop to shell when some
# specific events happen. They can be found at
# https://docs.angr.io/core-concepts/simulation#breakpoints
state.inspect.b('call', action=debug_call)
#state.inspect.b('exit',when=angr.BP_AFTER, action=debug_exit)
if stdout:
    find=is_successful
simulation_manager = p.factory.simgr(state)
simulation_manager.explore(find=find, avoid=avoid)

for found in simulation_manager.found:
    print(f"Found state {hex(found.addr)}")
    if interesting_value:
        print(found.solver.eval(interesting_value), cast_to=int)
    for arg in argv:
        print(found.solver.eval(arg, cast_to=bytes))
    for unconstrained in simulation_manager.unconstrained:
        print("Found unconstrained memory in state: {}".format(unconstrained))
        print("{}".format(unconstrained.regs.pc))

timer_end = time.time()
print(f"Time spent: {timer_end - timer_start}")