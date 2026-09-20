export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;

  for (let i = 0; i < String(text || '').length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        field += '"';
        i += 1;
      } else if (ch === '"') {
        quoted = false;
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') {
      quoted = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field.replace(/\r$/, ''));
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += ch;
    }
  }
  if (field.length || row.length) {
    row.push(field.replace(/\r$/, ''));
    rows.push(row);
  }
  return rows.filter((r) => r.some((v) => String(v).length > 0));
}

export function normalizeCandidateType(type, value) {
  const t = String(type || '').trim().toLowerCase();
  if (['ipv4', 'ip', 'ip-src', 'ip-dst'].includes(t)) return 'ipv4';
  if (['domain', 'hostname', 'fqdn'].includes(t)) return 'domain';
  if (['url', 'uri'].includes(t)) return 'url';
  if (['md5', 'sha1', 'sha256', 'hash'].includes(t)) return 'hash';

  const v = String(value || '').trim();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ipv4';
  if (/^https?:\/\//i.test(v)) return 'url';
  if (/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(v)) return 'hash';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return 'domain';
  return t || 'auto';
}

export function buildCandidatesFromIocCsv(text, limit = 32) {
  const rows = parseCsv(text);
  if (rows.length < 2) return [];

  const headers = rows[0].map((h) => String(h || '').trim().toLowerCase());
  const idx = Object.fromEntries(headers.map((h, i) => [h, i]));
  const valueIndex = idx.ioc_value;
  const typeIndex = idx.ioc_type;
  if (!Number.isInteger(valueIndex) || !Number.isInteger(typeIndex)) return [];

  const seen = new Set();
  const candidates = [];

  for (const row of rows.slice(1)) {
    const value = String(row[valueIndex] || '').trim();
    const rawType = String(row[typeIndex] || '').trim();
    if (!value || value.length > 256) continue;

    const type = normalizeCandidateType(rawType, value);
    const key = `${type}:${value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const reportId = String(row[idx.source_report_id] || '').trim();
    const cve = String(row[idx.cve_id] || '').trim();
    const actor = String(row[idx.actor_tag] || '').trim();
    const severity = String(row[idx.severity] || '').trim().toUpperCase();
    const risk = Number(row[idx.risk_score] || 0);

    let structuralScore = 0;
    if (reportId) structuralScore += 3;
    if (/^CVE-\d{4}-\d{4,}$/i.test(cve)) structuralScore += 3;
    if (actor && actor.toUpperCase() !== 'UNATTRIBUTED') structuralScore += 3;
    if (severity === 'CRITICAL') structuralScore += 2;
    else if (severity === 'HIGH') structuralScore += 1;
    if (Number.isFinite(risk) && risk >= 8) structuralScore += 2;
    else if (Number.isFinite(risk) && risk >= 6) structuralScore += 1;

    candidates.push({
      value,
      type,
      raw_type: rawType || null,
      report_id: reportId || null,
      cve_id: cve || null,
      actor_tag: actor || null,
      severity: severity || null,
      risk_score: Number.isFinite(risk) ? risk : null,
      structural_score: structuralScore,
    });
  }

  return candidates
    .sort((a, b) => b.structural_score - a.structural_score)
    .slice(0, Math.max(1, Number(limit) || 32));
}
