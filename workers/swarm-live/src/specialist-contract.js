// =============================================================================
// CYBERDUDEBIVASH SENTINEL APEX — SPECIALIST RESPONSE ADAPTERS
// V4.47.0
//
// Normalizes heterogeneous canonical gateway success envelopes into one
// internal contract used by SWARM orchestration. Backend APIs remain unchanged.
// =============================================================================

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

export function adaptSpecialistResponse(agentId, body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { success: false, substantive: false, data: null, count: 0, schema: 'invalid' };
  }

  let data = null;
  let schema = 'unknown';
  let success = false;

  switch (agentId) {
    case 'cve-intelligence':
      schema = 'cve-extension-v1';
      success = body.status === 'ok' && Array.isArray(body?.data?.cves);
      data = success ? body.data : null;
      break;

    case 'threat-hunter':
      schema = 'actor-extension-v1';
      success = body.status === 'ok' && Array.isArray(body?.data?.actors);
      data = success ? body.data : null;
      break;

    case 'attack-mapper':
      schema = 'search-extension-v1';
      success = body.status === 'ok' && Array.isArray(body?.data?.results);
      data = success ? body.data : null;
      break;

    case 'siem-defender':
      schema = 'detection-registry-v1';
      success =
        typeof body.schema_version === 'string' &&
        Array.isArray(body.data) &&
        body.pagination &&
        typeof body.pagination === 'object';
      data = success ? body.data : null;
      break;

    case 'ir-playbook':
      schema = 'ir-guidance-v1';
      success = body.status === 'ok' && body?.data && typeof body.data === 'object';
      data = success ? body.data : null;
      break;

    case 'exposure-analyst':
      schema = 'exposure-analysis-v1';
      success = body.status === 'ok' && body?.data && typeof body.data === 'object';
      data = success ? body.data : null;
      break;

    default:
      schema = 'generic-status-data-v1';
      success = body.status === 'ok' && Object.prototype.hasOwnProperty.call(body, 'data');
      data = success ? body.data : null;
      break;
  }

  let count = 0;
  let substantive = false;

  if (Array.isArray(data)) {
    count = data.length;
    substantive = data.length > 0;
  } else if (data && typeof data === 'object') {
    const nestedArrays = ['cves', 'actors', 'results']
      .map((key) => Array.isArray(data[key]) ? data[key] : null)
      .filter(Boolean);

    if (nestedArrays.length) {
      count = nestedArrays.reduce((sum, arr) => sum + arr.length, 0);
      substantive = count > 0;
    } else {
      count = 1;
      // IR/exposure may legitimately contain an object whose useful arrays are
      // empty; presence of the canonical report identity still makes the backend
      // execution real/substantive evidence.
      substantive = Boolean(
        data.report_id ||
        data.intel_id ||
        Object.keys(data).some((key) => {
          const value = data[key];
          return Array.isArray(value) ? value.length > 0 : value != null && value !== '';
        })
      );
    }
  } else if (data != null) {
    count = 1;
    substantive = true;
  }

  return {
    success,
    substantive: success && substantive,
    data,
    count,
    schema,
  };
}
