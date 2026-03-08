export function normalizeChoices(input, maxFields = 8) {
  const parsed = input
    .split(',')
    .map((s) => parseInt(s.trim(), 10))
    .map((v) => (Number.isFinite(v) ? v : 0))
    .slice(0, maxFields);

  const numFields = parsed.length;
  const choices = parsed.slice();
  while (choices.length < maxFields) {
    choices.push(0);
  }

  return { choices, numFields };
}

export function packBallotMode(config) {
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

function u64ToLeBytes(val) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, BigInt(val), true);
  return new Uint8Array(buf);
}
