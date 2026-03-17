export function normalizeChoices(input, maxFields = 8) {
  const parsed = input
    .split(',')
    .map((s) => s.trim())
    .map((s) => (s.length > 0 ? parseBigIntValue(s) : 0n))
    .slice(0, maxFields);

  const numFields = parsed.length;
  const choices = parsed.slice();
  while (choices.length < maxFields) {
    choices.push(0n);
  }

  return { choices, numFields };
}

export function packBallotMode(config) {
  assertBitWidth(config.numFields, 8, 'numFields');
  assertBitWidth(config.groupSize, 8, 'groupSize');
  assertBitWidth(config.uniqueValues, 1, 'uniqueValues');
  assertBitWidth(config.costFromWeight, 1, 'costFromWeight');
  assertBitWidth(config.costExponent, 8, 'costExponent');
  assertBitWidth(config.maxValue, 48, 'maxValue');
  assertBitWidth(config.minValue, 48, 'minValue');
  assertBitWidth(config.maxValueSum, 63, 'maxValueSum');
  assertBitWidth(config.minValueSum, 63, 'minValueSum');

  let bits = 0n;
  bits |= BigInt(config.numFields) & 0xFFn;
  bits |= (BigInt(config.groupSize) & 0xFFn) << 8n;
  bits |= (BigInt(config.uniqueValues) & 1n) << 16n;
  bits |= (BigInt(config.costFromWeight) & 1n) << 17n;
  bits |= (BigInt(config.costExponent) & 0xFFn) << 18n;
  bits |= (BigInt(config.maxValue) & 0xFFFFFFFFFFFFn) << 26n;
  bits |= (BigInt(config.minValue) & 0xFFFFFFFFFFFFn) << 74n;
  bits |= (BigInt(config.maxValueSum) & 0x7FFFFFFFFFFFFFFFn) << 122n;
  bits |= (BigInt(config.minValueSum) & 0x7FFFFFFFFFFFFFFFn) << 185n;

  const mask62 = (1n << 62n) - 1n;
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const chunk = (bits >> (BigInt(i) * 62n)) & mask62;
    const bytes = u64ToLeBytes(chunk);
    out.set(bytes, i * 8);
  }
  return out;
}

export function encodeGoldilocks4Le(value) {
  let remaining = BigInt(value);
  if (remaining < 0n) {
    throw new Error('value must be non-negative');
  }

  const out = new Uint8Array(32);
  const mask = (1n << 64n) - 1n;
  for (let i = 0; i < 4; i++) {
    const chunk = remaining & mask;
    out.set(u64ToLeBytes(chunk), i * 8);
    remaining >>= 64n;
  }
  if (remaining !== 0n) {
    throw new Error('value does not fit in 256 bits');
  }
  return out;
}

export function encodeU64LeChecked(value) {
  const normalized = BigInt(value);
  if (normalized < 0n) {
    throw new Error('value must be non-negative');
  }
  if (normalized >> 64n) {
    throw new Error('value does not fit in u64');
  }
  return u64ToLeBytes(normalized);
}

export function parseBigIntValue(raw) {
  const value = raw.trim();
  if (!value) {
    return 0n;
  }
  if (value.startsWith('0x') || value.startsWith('0X')) {
    return BigInt(value);
  }
  return BigInt(value);
}

function assertBitWidth(value, bits, name) {
  const normalized = BigInt(value);
  if (normalized < 0n) {
    throw new Error(`${name} must be non-negative`);
  }
  if (normalized >> BigInt(bits)) {
    throw new Error(`${name} does not fit in ${bits} bits`);
  }
}

function u64ToLeBytes(val) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, BigInt(val), true);
  return new Uint8Array(buf);
}
