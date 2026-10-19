/** Pure, offline aggregation of existing P20-P26 gate verdicts. */
export function summarizePublicationGate({ results, successfulEndpoints, expectedEndpoints, errors = [] }) {
  if (!Array.isArray(results) || !Array.isArray(successfulEndpoints) ||
      !Array.isArray(expectedEndpoints) || !Array.isArray(errors)) {
    throw new TypeError('Invalid publication audit inputs');
  }
  const expected = new Set(expectedEndpoints);
  const successful = new Set(successfulEndpoints);
  const incomplete = expected.size === 0 || expected.size !== successful.size ||
    [...expected].some(endpoint => !successful.has(endpoint)) || errors.length > 0 || results.length === 0;
  const counts = { CUSTOMER_READY: 0, REJECTED: 0, BLOCKED: 0, INVALID: 0 };
  const reasonCounts = new Map();
  const withheldSamples = [];
  const uniqueIds = new Set();
  for (const result of results) {
    const state = result?.publication_state;
    const ready = result?.customer_ready;
    const id = result?.report_id;
    if (typeof id !== 'string' || !id || uniqueIds.has(id) ||
        typeof ready !== 'boolean' || !['CUSTOMER_READY', 'REJECTED', 'BLOCKED'].includes(state) ||
        (ready !== (state === 'CUSTOMER_READY')) || !Array.isArray(result.blocking_gates) ||
        result.blocking_gates.some(x => typeof x !== 'string' || !/^[A-Z0-9_]{2,100}$/.test(x)) ||
        (ready && result.blocking_gates.length !== 0) ||
        (!ready && result.blocking_gates.length === 0)) {
      counts.INVALID++;
      continue;
    }
    uniqueIds.add(id);
    counts[state]++;
    if (!ready) {
      if (withheldSamples.length < 8) withheldSamples.push({ report_id: id, state, reason_codes: result.blocking_gates });
      for (const reason of new Set(result.blocking_gates)) reasonCounts.set(reason, (reasonCounts.get(reason) || 0) + 1);
    }
  }
  const reason_counts = Object.fromEntries([...reasonCounts].sort((a,b)=>b[1]-a[1] || a[0].localeCompare(b[0])));
  const coverageOK = !incomplete && counts.INVALID === 0;
  const verdict = !coverageOK ? 'INCONCLUSIVE_INCOMPLETE_AUDIT' :
    counts.REJECTED + counts.BLOCKED > 0 ? 'WITHHELD_BY_PUBLICATION_GATE' : 'LOCAL_GATE_PRECHECK_ONLY';
  return {
    verdict, exit_code: !coverageOK ? 2 : verdict === 'WITHHELD_BY_PUBLICATION_GATE' ? 1 : 0,
    scope: 'Current latest/top10/apex feed windows only; no report-object GET or customer delivery certification',
    endpoint_count: expected.size, endpoints_succeeded: [...successful].filter(x=>expected.has(x)).sort(),
    endpoints_missing: [...expected].filter(x=>!successful.has(x)).sort(),
    fetch_error_count: errors.length, candidates_evaluated: results.length,
    customer_ready: counts.CUSTOMER_READY, rejected: counts.REJECTED, blocked: counts.BLOCKED,
    malformed_or_conflicting: counts.INVALID, reason_counts, withheld_samples: withheldSamples,
    report_delivery_certified: false,
  };
}
