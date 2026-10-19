import json
from pathlib import Path
import pytest
from scripts.publish_customer_engine_evidence import publish

@pytest.mark.parametrize('envelope',['entries','advisories','items'])
def test_manifest_publishes_measured_schemas_without_legacy_claims(tmp_path,envelope):
    p=tmp_path/'manifest.json';p.write_text(json.dumps({envelope:[{'id':'a','title':'CVE-2026-1234','source_url':'https://example.test/a'}]}))
    outputs=publish(p,tmp_path)
    for name,d in outputs.items():
        assert json.loads((tmp_path/name).read_text())==d
        assert d['input_evidence']['record_count']==1
        assert not any(k in d for k in ['billing','tenants','compliance','feed_trust','false_positives','stream'])
    assert outputs['data/cortex/cortex_output.json']['knowledge_graph']['total_edges']==1

@pytest.mark.parametrize('raw',[[],{}, {'entries':{}}, {'entries':[None]}, {'advisories':[]}, {'items':{}}, {'advisories':None, 'items':[{'title':'untrusted fallback'}]}])
def test_invalid_manifest_blocks_publication_and_preserves_saved_output(tmp_path,raw):
    p=tmp_path/'manifest.json';p.write_text(json.dumps(raw))
    saved=tmp_path/'data/cortex/cortex_output.json';saved.parent.mkdir(parents=True);saved.write_text('saved')
    with pytest.raises(ValueError):publish(p,tmp_path)
    assert saved.read_text()=='saved'

def test_publication_precedes_validation_and_upload_in_existing_workflow():
    s=(Path(__file__).resolve().parents[1]/'.github/workflows/sovereign-platform.yml').read_text()
    call=s.index('run: python3 scripts/publish_customer_engine_evidence.py')
    assert call < s.index('python3 scripts/validate_intelligence_plane_output.py --file data/cortex') < s.index('python3 scripts/r2_state_sync.py --upload')
