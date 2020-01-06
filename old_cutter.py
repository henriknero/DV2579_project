#!/usr/bin/env python

import angr
import claripy
import os
import sys
import time
import logging
import argparse

logger = logging.getLogger(__name__)
logging.getLogger('angr').setLevel('ERROR')

stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']
visited_list = []
backward_slice = {}
interesting_function = 0x400590
interesting_value = claripy.BVS('regs.rsi', 64)

def main(args):
    logger.setLevel(logging.WARNING - args.v*10)
    target = args.target
    path = args.file
    avoid = None
    sym_argv = []
    global backward_slice
    if args.argv:
        sym_argv = [claripy.BVS('sym_argv', x * 8) for x in args.argv]

    p = angr.Project(path)
    if args.acfg:
        acfg = build_acfg(p, target)
        backward_slice = acfg._exit_taken
    elif args.simple_acfg:
        acfg = build_simple_acfg(p, target)
        backward_slice = acfg._exit_taken
    elif args.simple_slicer:
        cfg = p.analyses.CFGEmulated(keep_state=True)
        target_node = cfg.model.get_any_node(target, anyaddr=True)
        get_predecessors(target_node)
        backward_slice[target_node.addr], backward_slice[target] = 0, 0
    avoid=not_in_path
    if not any([args.acfg, args.simple_acfg, args.simple_slicer]):
        avoid=None

    state = p.factory.entry_state(args=[p.filename]+sym_argv)
    state.inspect.b('call', action=debug_function)
    simulation_manager = p.factory.simgr(state, veritesting=True)
    simulation_manager.explore(find=target, avoid=avoid)
    for found in simulation_manager.found:
        print(f"Found State {hex(found.addr)}")
        for index, argv in enumerate(sym_argv):
            print(f'Argv[{index}]: ',found.solver.eval(argv, cast_to=bytes))
    for dd in simulation_manager.deadended:
        print(f"Deadended State {hex(dd.addr)}")
        for index, argv in enumerate(sym_argv):
            print(f'Argv[{index}]: ',dd.solver.eval(argv, cast_to=bytes))
    for avoid in simulation_manager.avoid:
        print(f"Avoided State {hex(avoid.addr)}:")
        for index, argv in enumerate(sym_argv):
            print(f'Argv[{index}]: ',avoid.solver.eval(argv, cast_to=bytes))
        
def not_in_path(state):
    if state.addr not in backward_slice:
        logger.info("Avoid block %#x found and avoided.", state.addr)
        return True

def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Bomb' in stdout_output

def build_acfg(p, target):
    logger.info('Building CFG, CDG and DDG to generate AnnotedCFG, depending on size of binary this may take some time.')
    cfg = p.analyses.CFGEmulated(keep_state=True)
    target_node = cfg.model.get_any_node(target, anyaddr=True)
    cdg = p.analyses.CDG(cfg)
    ddg = p.analyses.DDG(cfg)
    bs = p.analyses.BackwardSlice(cfg, cdg, ddg, targets=[(target_node, -2)])
    return bs.annotated_cfg()

def build_simple_acfg(p, target):
    logger.info('Building CFG, CDG and DDG to generate AnnotedCFG, depending on size of binary this may take some time.')
    cfg = p.analyses.CFGEmulated(keep_state=True)
    target_node = cfg.model.get_any_node(target, anyaddr=True)
    #Workaround angr forcing you to supply cdg and dd when it's actually not needed for control_flow_slice
    cdg = None
    ddg = None
    bs = p.analyses.BackwardSlice(cfg, cdg, ddg, targets=[(target_node, -1)], control_flow_slice=True)
    return bs.annotated_cfg()

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
        logger.debug("Call to %s", state)




if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--acfg', action='store_true', help='Use the built in analysis tools to build a backward slice of the program. There are some bugs in the analysis causing it to miss variables sometimes. If this does not work remove it and try using my simpler backward slicer algorithm with --simple-slice')
    parser.add_argument('--simple-acfg', action='store_true', help='Use the built in analysis tools to build a backward slice of the program. There are some bugs in the analysis causing it to miss variables sometimes. If this does not work remove it and try using my simpler backward slicer algorithm with --simple-slice')
    parser.add_argument('--simple-slicer', action='store_true', help='Uses the control flow graph of the program to build a traversal map for the explorer to take')
    #parser.add_argument('--nuclear-bomb', action='store_true', help='I have become death, destroyer of worlds(Just try everything...)')
    parser.add_argument('--target', help='Sets the target to the address in the program that you want to find.')
    parser.add_argument('--argv',nargs='+',type=int, help='Array of integers telling the script number of arguments and size of each argument. E.g. \"--argv 12 7\" tells the program that argv[1] is 7 chars long Bytevector and argv[2] is 12 chars long')
    parser.add_argument('file')
    parser.add_argument('-v', action='count', default=0, help='Change verbosity of script, -v for informational and -vv for debug')
    args = parser.parse_args()
    try:
        args.target = int(args.target, base=16)
    except:
        args.target = int(args.target)
    print(args)
    start = time.time()
    main(args)
    if time.time() - start < 60:
        print("Time taken: ", time.time() - start)
    else:
        print("Timeout after 60")
    print()

    