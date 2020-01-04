#!/usr/bin/env python

import angr
import claripy
import time
import logging

stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']

def main():
    path = "C:\\Users\\John\\DV2579_project\\MyDoom\\strip-girl-2.0bdcom_patches.exe"
    find = 0x004a3de3

    p = angr.Project(path, auto_load_libs=False)

    print('Generating CFGEmulated')
    cfg = p.analyses.CFGEmulated(keep_state=True)
    acfg = build_acfg(p, cfg, find)
    debug_addr = 0x4a4001
    
    p = angr.Project(path)
    stub_functions(p, [0x004a465e,0x004a3962, 0x004a3b88])
    print(p.loader.find_symbol('lstrlenA').linked_addr)
    state = p.factory.entry_state(args=[p.filename])
    #state.inspect.b('call', action=debug_function)
    #state.inspect.b('exit', action=fork_function)

    simulation_manager = p.factory.simgr(state, veritesting=True)

    #simulation_manager.explore(find=find, avoid=avoid)
    simulation_manager.found = []
    while not simulation_manager.found:
        for active_state in simulation_manager.active:
            print("Current Block:", hex(active_state.addr))
            print(active_state.block().pp())
            print([hex(x) for x in acfg._exit_taken[active_state.addr] if active_state.addr in acfg._exit_taken])
            if active_state.addr == debug_addr:
                print("Debug")
        simulation_manager.step()

def stub_functions(p, addresses):
    for address in addresses:
        p.hook(address, stub_func())

def build_acfg(p, cfg, find):
    print('Generating CDG')
    #cdg = p.analyses.CDG(cfg)
    print('Generating DDG')
    #ddg = p.analyses.DDG(cfg)

    print('Finding node')
    target_node = cfg.model.get_any_node(find, anyaddr=True)

    back_slice = p.analyses.BackwardSlice(cfg, targets=[(target_node,-1)], control_flow_slice=True)
    return back_slice.annotated_cfg()


def debug_function(state):
    if state.addr < 0x1000000:
        print("Call to %s" % state)

def fork_function(state):
    print("Forking has been done in block %s" % state.addr)


if __name__ == "__main__":
    main()

#    for found in simulation_manager.found:
#        print("dwHighDateTime")
#        print(" ",found.solver.min(found.solver.constraints[42].args[0]))
#        print("dwLowDateTime")
#        print(" ",found.solver.min(found.regs.eax))