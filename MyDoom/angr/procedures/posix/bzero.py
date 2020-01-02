from ..libc import memset

class bzero(memset.memset):
    def run(self, addr, size):
        return super(bzero, self).run(addr, self.state.solver.BVV(0, self.arch.byte_width), size)
