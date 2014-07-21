# http://codegolf.stackexchange.com/questions/4732/emulate-an-intel-8086-cpu?newreg=878716d5c6bb4c1dbec736e6889619b4
import os
import proc
import memory


class Emu:
    def __init__(self, proc, mem):
        self.cpu = proc
        self.mem = mem

    def start(self, rom):
        self.mem.load_rom(rom)
        self.cpu.reset()

        self._do_machine_cycle()

    # fetch-decode-execute cycle
    def _do_machine_cycle(self):
        while True:
            self.cpu.fetch_instr()
            # print ':'.join(x.encode('hex') for x in word)
            self.cpu.decode_instr()
            self.cpu.execute_instr()


####################### Run ########################

def start(rom):
    mem = memory.Ram()
    cpu = proc.Proc86(mem, proc.InstructionDecoder(), proc.Alu())
    emulator = Emu(cpu, mem)
    emulator.start(rom)

if __name__ == '__main__':
    start(os.path.dirname(__file__) + '/codegolf')
