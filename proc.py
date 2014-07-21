import collections

Instr = collections.namedtuple('Instr', ['opcode', 'operands'])


def mod_byte_get_mod(word):
    return (word[1] & 0b11000000) >> 6


def mod_byte_get_reg_opcode(word):
    return (word[1] & 0b00111000) >> 3


def mod_byte_get_r_m(word):
    return word[1] & 0b00000111


def bytes_to_int(bytes):
    acc = 0
    for b, i in enumerate(bytes):
        acc |= b << (i << 3)

    return acc

def msb(val, size=16):
    return val & (1 << size - 1)


class Proc86:
    FLAG_CARRY = 0
    FLAG_PARITY = 2
    FLAG_ZERO = 6
    FLAG_SIGN = 7

    # main registers
    ax = 0  # primary accumulator
    bx = 0  # base, accumulator
    cx = 0  # counter, accumulator
    dx = 0  # accumulator, other functions

    # index registers
    si = 0  # Source Index
    di = 0  # Destination Index
    bp = 0  # Base Pointer
    sp = 0  # Stack Pointer

    # Program counter
    ip = 0  # Instruction Pointer

    # Segment registers
    cs = 0  # Code Segment
    ds = 0  # Data Segment
    es = 0  # Extra Segment
    ss = 0  # Stack Segment

    # Status register
    flags = 0  # - - - - O D I T S Z - A - P - C   Flags

    mar = 0  # Memory Access Register
    mdr = 0  # Memory Data Register
    cir = 0  # Current Instruction Register - instruction currently being executed or decoded

    def __init__(self, memory, cu, alu, word_size=16, ip=0, sp=0x100):
        self.word_size = word_size >> 3
        self.word_size_bits = word_size
        self._initial_ip = ip
        self._initial_sp = sp
        self.reset()
        self.memory = memory
        self.instr_decoder = cu
        self.alu = alu

        self.instr_decoder.init(self, memory)
        self.alu.init(self)

    def decode_instr(self):
        self.cir = self.instr_decoder.decode(self.cir)
        if not self.cir:
            raise Exception('Unexpected opcode [' + self._repr_byte_array(self.mdr) + ']')

    def execute_instr(self):
        self.alu.execute()

    def fetch_instr(self):
        self.mar = self.ip
        self.fetch_mem()
        self.cir = self.mdr

    def fetch_mem(self):
        self.mdr = self.memory.read(self.mar, self.word_size)

    def reset(self):
        self.ip = self._initial_ip
        self.sp = self._initial_sp

    def reset_flags(self):
        self.flags = 0

    def set_parity_flag(self, val):
        bit = 0
        for i in xrange(0, self.word_size_bits - 1):
            bit ^= (val & (1 << i))

        self.flags |= bit << Proc86.FLAG_PARITY

    def set_sign_flag(self, val):
        self.flags |= msb(val) << Proc86.FLAG_SIGN

    def set_zero_flag(self, val):
        self.flags |= int(0 == val) << Proc86.FLAG_ZERO

    # returns True if flag is equals to 1
    def test_zero_flag(self):
        return 0 != (self.flags & (1 << Proc86.FLAG_ZERO))

    @staticmethod
    def _repr_byte_array(bytes):
        return ''.join(format(b, '02x') for b in bytes)


class Alu:
    def __init__(self):
        self.cpu = None

        self.micro_codes = {
            'cmp': self._cmp,
            'js': self._js
        }

    def init(self, cpu):
        self.cpu = cpu

    def execute(self):
        method = self.micro_codes.get(self.cpu.cir.opcode)
        if not method:
            raise Exception('Unexpected micro program [' + self.cpu.cir + ']')

        method(self.cpu.cir.operands)

    def _cmp(self, operands):
        temp = operands[0] - operands[1]

        self.cpu.reset_flags()
        self.cpu.set_sign_flag(temp)
        self.cpu.set_zero_flag(temp)
        self.cpu.set_parity_flag(temp)

    # Jump short if zero/equal (ZF=0)
    def _js(self, operands):
        if self.cpu.test_zero_flag():
            self.cpu.ip += operands[0]

class InstructionDecoder:  # aka Control Unit (CU)
    def __init__(self, ):
        self.cpu = None
        self.memory = None

        self.opcodes = {
            0x81: self._decode0x81,
            0x74: self._decode_js_Jbs
        }

        self.opcodes_ext = {
            0x81: {
                7: self._decode_cmp_Ev_Iv
            }
        }

        # only for 16-bit CPU
        self.mod_rm_byte_reg = {
            0b000: 'ax',
            0b001: 'cx',
            0b010: 'dx',
            0b011: 'bx',
            0b100: 'sp',
            0b101: 'bp',
            0b110: 'si',
            0b111: 'di'
        }

    def init(self, cpu, memory):
        self.cpu = cpu
        self.memory = memory

    def decode(self, word):
        method = self.opcodes.get(word[0])
        if not method:
            return None

        return method(word)

    def _decode0x81(self, word):
        # use ModR\M byte to extend opcodes range
        ext = self.opcodes_ext.get(word[0])
        if not ext: return None

        decoder = ext.get(mod_byte_get_reg_opcode(word))
        return decoder(word) if decoder else None

    # E means taking in account ModR\M byte following the opcode
    # I means immediate memory arg (v - word or dword)
    # I.e. we need to compare some register and immediate value from memory
    def _decode_cmp_Ev_Iv(self, word):
        # load immediate value (rvalue)
        self.cpu.mar = self.cpu.ip + len(word)
        self.cpu.fetch_mem()

        r_value = self.cpu.mdr
        self.cpu.ip += len(word) + len(r_value)

        l_value = getattr(self.cpu, self.mod_rm_byte_reg[mod_byte_get_r_m(word)])

        return Instr('cmp', [l_value, bytes_to_int(r_value)])

    # J  - The instruction contains a relative offset to be added to the instruction pointer register
    # bs - Byte, sign-extended to the size of the destination operand.
    def _decode_js_Jbs(self, word):
        self.cpu.ip += len(word)

        return Instr('js', [int(word[1])])