import argparse
import math

rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

constants = [int(abs(math.sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

init_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

functions = 16*[lambda b, c, d: (b & c) | (~b & d)] + \
            16*[lambda b, c, d: (d & b) | (~d & c)] + \
            16*[lambda b, c, d: b ^ c ^ d] + \
            16*[lambda b, c, d: c ^ (b | ~d)]

index_functions = 16*[lambda i: i] + \
                  16*[lambda i: (5*i + 1)%16] + \
                  16*[lambda i: (3*i + 5)%16] + \
                  16*[lambda i: (7*i)%16]


def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x<<amount) | (x>>(32-amount))) & 0xFFFFFFFF


def right_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x >> amount) | (x << (32 - amount)))


def md5(message):
    message = bytearray(message, "UTF8")  # copy our input into a mutable buffer
    orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += orig_len_in_bits.to_bytes(8, byteorder='little')

    hash_pieces = init_values[:]

    print(bytes.hex(hash_pieces[0].to_bytes(length=4, byteorder='little')), bytes.hex(hash_pieces[1].to_bytes(length=4, byteorder='little')),
          bytes.hex(hash_pieces[2].to_bytes(length=4, byteorder='little')), bytes.hex(hash_pieces[3].to_bytes(length=4, byteorder='little')))

    for chunk_ofst in range(0, len(message), 64):
        a, b, c, d = hash_pieces
        chunk = message[chunk_ofst:chunk_ofst + 64]
        for i in range(64):
            f = functions[i](b, c, d)
            g = index_functions[i](i)
            to_rotate = a + f + constants[i] + int.from_bytes(chunk[4 * g:4 * g + 4], byteorder='little')
            new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF
            a, b, c, d = d, new_b, b, c
            print(bytes.hex(a.to_bytes(length=4, byteorder='little')), bytes.hex(b.to_bytes(length=4, byteorder='little')),
                  bytes.hex(c.to_bytes(length=4, byteorder='little')), bytes.hex(d.to_bytes(length=4, byteorder='little')))
        for i, val in enumerate([a, b, c, d]):
            hash_pieces[i] += val
            hash_pieces[i] &= 0xFFFFFFFF


    return (sum(x << (32 * i) for i, x in enumerate(hash_pieces))).to_bytes(16, byteorder='little')


def create_chunk(message):
    message = bytearray(message, "UTF8")
    orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += orig_len_in_bits.to_bytes(8, byteorder='little')
    chunk = message[0:64]
    return chunk


def md5_rollback_till(hash, till_number, message):
    a, b, c, d = [hash[:4], hash[4:8], hash[8:12], hash[12:]]

    a = (int.from_bytes(a, byteorder='little') - init_values[0]) & 0xFFFFFFFF
    b = (int.from_bytes(b, byteorder='little') - init_values[1]) & 0xFFFFFFFF
    c = (int.from_bytes(c, byteorder='little') - init_values[2]) & 0xFFFFFFFF
    d = (int.from_bytes(d, byteorder='little') - init_values[3]) & 0xFFFFFFFF

    print(bytes.hex(a.to_bytes(length=4, byteorder='little')), bytes.hex(b.to_bytes(length=4, byteorder='little')),
          bytes.hex(c.to_bytes(length=4, byteorder='little')), bytes.hex(d.to_bytes(length=4, byteorder='little')))

    chunk = create_chunk(message)

    for i in range(63, till_number - 1, -1):  # begins calculate from Q_59
        from_rotate = right_rotate(b - c, rotate_amounts[i])
        f = functions[i](c, d, a)
        g = index_functions[i](i)
        ch = chunk[4 * g:4 * g + 4]
        previous_a = ((from_rotate - f) - constants[i]) - int.from_bytes(ch, byteorder='little') & 0xFFFFFFFF
        a, b, c, d = previous_a, c, d, a

        a &= 0xFFFFFFFF
        b &= 0xFFFFFFFF
        c &= 0xFFFFFFFF
        d &= 0xFFFFFFFF

        print(bytes.hex(a.to_bytes(length=4, byteorder='little')), bytes.hex(b.to_bytes(length=4, byteorder='little')), bytes.hex(c.to_bytes(length=4, byteorder='little')), bytes.hex(d.to_bytes(length=4, byteorder='little')))

    a &= 0xFFFFFFFF
    b &= 0xFFFFFFFF
    c &= 0xFFFFFFFF
    d &= 0xFFFFFFFF

    return sum(x << (32 * i) for i, x in enumerate([a, b, c, d])).to_bytes(16, 'little')


def hash_and_reverse(message):
    print("hashing:\n")
    message_hash = md5(message)
    print("\nrollback:\n")
    md5_rollback_till(message_hash, 0, message)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.version = '1.0'
    parser.add_argument('--message',
                        action='store',
                        type=str,
                        required=True,
                        help='set the hash for recovery (in hex)')

    args = parser.parse_args()
    hash_and_reverse(args.message)

