// Keccak-256 as Ethereum uses it: legacy Keccak padding (0x01), not FIPS
// SHA-3 padding (0x06). Pure TypeScript, no dependencies.

const RATE_BYTES = 136;
const MASK_64 = (1n << 64n) - 1n;

const ROUND_CONSTANTS: readonly bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
  0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
  0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
  0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
] as const;

const RHO_OFFSETS: readonly number[] = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
] as const;

function rotateLeft64(value: bigint, amount: number): bigint {
  if (amount === 0) return value & MASK_64;
  const shift = BigInt(amount);
  return ((value << shift) | (value >> (64n - shift))) & MASK_64;
}

function permutation(state: bigint[]): void {
  let lanes = state.slice();
  for (const roundConstant of ROUND_CONSTANTS) {
    const column = new Array<bigint>(5).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      column[x] = lanes[x]! ^ lanes[x + 5]! ^ lanes[x + 10]!
        ^ lanes[x + 15]! ^ lanes[x + 20]!;
    }
    const delta = new Array<bigint>(5).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      delta[x] = column[(x + 4) % 5]! ^ rotateLeft64(column[(x + 1) % 5]!, 1);
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const index = x + 5 * y;
        lanes[index] = (lanes[index]! ^ delta[x]!) & MASK_64;
      }
    }
    const moved = new Array<bigint>(25).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const from = x + 5 * y;
        const to = y + 5 * ((2 * x + 3 * y) % 5);
        moved[to] = rotateLeft64(lanes[from]!, RHO_OFFSETS[from]!);
      }
    }
    const next = new Array<bigint>(25).fill(0n);
    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        const index = x + 5 * y;
        next[index] = (
          moved[index]!
          ^ ((~moved[((x + 1) % 5) + 5 * y]!)
            & moved[((x + 2) % 5) + 5 * y]!)
        ) & MASK_64;
      }
    }
    next[0] = (next[0]! ^ roundConstant) & MASK_64;
    lanes = next;
  }
  for (let index = 0; index < 25; index += 1) state[index] = lanes[index]!;
}

function absorbBlock(state: bigint[], block: Buffer): void {
  for (let offset = 0; offset < RATE_BYTES; offset += 8) {
    const lane = offset / 8;
    state[lane] = (state[lane]! ^ block.readBigUInt64LE(offset)) & MASK_64;
  }
  permutation(state);
}

export function keccak256(input: Uint8Array | string): Buffer {
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
  const state = new Array<bigint>(25).fill(0n);
  let offset = 0;
  while (offset + RATE_BYTES <= bytes.length) {
    absorbBlock(state, bytes.subarray(offset, offset + RATE_BYTES));
    offset += RATE_BYTES;
  }
  const tail = Buffer.alloc(RATE_BYTES);
  bytes.copy(tail, 0, offset);
  tail[bytes.length - offset] = tail[bytes.length - offset]! ^ 0x01;
  tail[RATE_BYTES - 1] = tail[RATE_BYTES - 1]! ^ 0x80;
  absorbBlock(state, tail);
  const output = Buffer.alloc(32);
  for (let lane = 0; lane < 4; lane += 1) {
    output.writeBigUInt64LE(state[lane]!, lane * 8);
  }
  return output;
}

export function keccak256Hex(input: Uint8Array | string): string {
  return keccak256(input).toString("hex");
}
