import angr
import logging 
logging.getLogger('angr').setLevel('ERROR')
target = 0x004A3DB0

p = angr.Project('strip-girl-2.0bdcom_patches.exe', auto_load_libs=True)

print('Generating CFGEmulated')
cfg = p.analyses.CFGEmulated(keep_state=True)

print('Generating CDG')
cdg = p.analyses.CDG(cfg)
print('Generating DDG')
ddg = p.analyses.DDG(cfg)

print('Finding node')
target_node = cfg.model.get_any_node(target, anyaddr=True)

back_slice = p.analyses.BackwardSlice(cfg, cdg, ddg, targets=[(target_node,-1)])
