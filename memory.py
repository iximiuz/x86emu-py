import os


class Ram:
    def __init__(self, max_size=2 ** 16):
        self.max_size = max_size
        self.data = bytearray()

    def load_rom(self, rom):
        if os.path.getsize(rom) > self.max_size:
            raise Exception('rom image too big')

        f = open(rom, 'rb')
        self.data = bytearray(f.read()) # todo: use mmap

    def read(self, address, bytes_count):
        return self.data[address:address + bytes_count]


