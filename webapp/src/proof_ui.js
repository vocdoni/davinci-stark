export function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function formatProofPreview(bytes, prefixBytes = 32) {
  const shown = bytes.subarray(0, Math.min(bytes.length, prefixBytes));
  return `${bytesToHex(shown)}...`;
}

export function summarizeTimings(timings) {
  return Object.fromEntries(
    Object.entries(timings).map(([key, value]) => [key, Number(value).toFixed(2)]),
  );
}

export function buildWorkerResultMessage(id, proofData, timings) {
  return {
    message: {
      type: 'result',
      id,
      result: { proofData, timings },
    },
    transfer: [proofData.buffer],
  };
}

export function formatBuildCommit(commit) {
  if (!commit || commit === 'unknown') {
    return 'unknown';
  }
  return commit.slice(0, 12);
}
