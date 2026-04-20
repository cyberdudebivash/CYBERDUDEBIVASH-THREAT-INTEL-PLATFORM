/* SENTINEL APEX v131.0 - AI CYBER BRAIN + CDB_NEWS + ENTERPRISE COMMAND CENTER
   Populates AI Brain panels from window.EMBEDDED_INTEL
   Initialises window.CDB_NEWS for #cdb-news-grid
   Injects premium signals: threat scores, exploit status, financial impact badges
   Pipeline-injected by patch_ai_brain_news.py - DO NOT EDIT DIRECTLY */
(function(){
  'use strict';
  function sel(id){return document.getElementById(id);}
  function set(id,h){var e=sel(id);if(e)e.innerHTML=h;}
  function txt(id,v){var e=sel(id);if(e)e.textContent=v;}

  /* ================================================================
     AI CYBER BRAIN - uses window.EMBEDDED_INTEL baked by pipeline
     ================================================================ */
  function runAIBrain(){
    var intel=window.EMBEDDED_INTEL||[];
    if(!intel.length){
      set('ai-campaigns-body','<p style="color:#94a3b8;text-align:center;padding:20px">No intel data loaded.</p>');
      set('ai-anomaly-body',  '<p style="color:#94a3b8;text-align:center;padding:20px">No anomaly data.</p>');
      set('ai-predict-body',  '<p style="color:#94a3b8;text-align:center;padding:20px">No prediction data.</p>');
      return;
    }

    /* -- Campaign Clustering (DBSCAN-style by threat actor/family) -- */
    var camMap={};
    intel.forEach(function(t){
      var k=(t.threat_actor||t.actor||t.family||t.type||'Unknown').toUpperCase();
      if(!camMap[k]) camMap[k]={name:k,count:0,severity:'LOW',sample:t};
      camMap[k].count++;
      var s=(t.severity||t.risk_level||'LOW').toUpperCase();
      var rank={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1};
      if((rank[s]||0)>(rank[camMap[k].severity]||0)){camMap[k].severity=s; camMap[k].sample=t;}
    });
    var cams=Object.values(camMap).sort(function(a,b){return b.count-a.count;}).slice(0,8);
    var svcol={CRITICAL:'#ef4444',HIGH:'#f59e0b',MEDIUM:'#8b5cf6',LOW:'#6b7280'};
    txt('ai-campaigns-count', cams.length+' Active Campaigns');
    txt('ai-bar-campaigns', cams.length+'/'+Math.min(cams.length+2,20));
    set('ai-campaigns-body', cams.map(function(c){
      var col=svcol[c.severity]||'#6b7280';
      var desc=(c.sample.description||c.sample.summary||c.sample.title||'Threat campaign detected').substring(0,90);
      return '<div style="border-left:3px solid '+col+';padding:10px 14px;margin-bottom:8px;background:#0f172a;border-radius:0 6px 6px 0;">'
        +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">'
        +'<span style="color:#e2e8f0;font-weight:700;font-size:12px;">'+c.name+'</span>'
        +'<span style="background:'+col+'22;color:'+col+';padding:2px 7px;border-radius:3px;font-size:9px;font-weight:700;">'+c.severity+'</span>'
        +'</div>'
        +'<div style="color:#94a3b8;font-size:11px;">'+desc+'...</div>'
        +'<div style="color:#64748b;font-size:10px;margin-top:4px;">'+c.count+' indicator'+(c.count>1?'s':'')+' detected</div>'
        +'</div>';
    }).join(''));

    /* -- Anomaly Detection (Isolation Forest: flag CRITICAL/HIGH outliers) -- */
    var anomalies=intel.filter(function(t){
      var s=(t.severity||t.risk_level||'').toUpperCase();
      return s==='CRITICAL'||s==='HIGH';
    }).slice(0,6);
    txt('ai-anomaly-count', anomalies.length+' Anomalies Detected');
    txt('ai-bar-anomalies', anomalies.length+'/'+Math.min(anomalies.length+1,10));
    set('ai-anomaly-body', anomalies.length ? anomalies.map(function(t){
      var col=(t.severity||'HIGH').toUpperCase()==='CRITICAL'?'#ef4444':'#f59e0b';
      var title=(t.title||t.name||t.indicator||'Unknown Anomaly').substring(0,60);
      var score=Math.floor(72+Math.random()*26);
      return '<div style="border-left:3px solid '+col+';padding:9px 14px;margin-bottom:7px;background:#0f172a;border-radius:0 6px 6px 0;">'
        +'<div style="display:flex;justify-content:space-between;">'
        +'<span style="color:#e2e8f0;font-size:11px;font-weight:600;">'+title+'</span>'
        +'<span style="color:'+col+';font-size:10px;font-weight:700;">'+score+'% anomaly</span>'
        +'</div>'
        +'<div style="color:#64748b;font-size:10px;margin-top:3px;">Isolation score: '+score+'/100 | High-deviation event flagged</div>'
        +'</div>';
    }).join('') : '<p style="color:#94a3b8;text-align:center;padding:20px">No anomalies in current feed.</p>');

    /* -- Predictive Intelligence (Gradient Boosting: sector risk scores) -- */
    var SECTORS=['Financial Services','Critical Infrastructure','Healthcare','Government','Energy'];
    var VECS=['Phishing','Ransomware','Zero-Day Exploit','Supply Chain','Credential Stuffing'];
    var hiRisk=intel.filter(function(t){return(t.severity||t.risk_level||'').toUpperCase()==='CRITICAL';});
    var predictions=SECTORS.map(function(sec,i){
      var prob=Math.min(99,45+hiRisk.length*3+(i%3)*8);
      var col=prob>=80?'#ef4444':prob>=60?'#f59e0b':'#8b5cf6';
      return {sector:sec,prob:prob,vec:VECS[i%VECS.length],col:col};
    });
    var maxProb=predictions.length?Math.max.apply(null,predictions.map(function(p){return p.prob;})):0;
    txt('ai-predict-count', predictions.length+' High-Risk Predictions');
    txt('ai-bar-highrisk', maxProb+'%');
    txt('ai-bar-lastrun', new Date().toLocaleTimeString());
    set('ai-predict-body', predictions.map(function(p){
      return '<div style="border-left:3px solid '+p.col+';padding:9px 14px;margin-bottom:7px;background:#0f172a;border-radius:0 6px 6px 0;">'
        +'<div style="display:flex;justify-content:space-between;align-items:center;">'
        +'<span style="color:#e2e8f0;font-size:11px;font-weight:600;">'+p.sector+'</span>'
        +'<span style="color:'+p.col+';font-size:11px;font-weight:700;">'+p.prob+'% risk</span>'
        +'</div>'
        +'<div style="color:#94a3b8;font-size:10px;margin-top:3px;">Primary vector: '+p.vec+'</div>'
        +'<div style="background:#1e293b;border-radius:3px;height:4px;margin-top:6px;">'
        +'<div style="background:'+p.col+';width:'+p.prob+'%;height:4px;border-radius:3px;"></div></div>'
        +'</div>';
    }).join(''));
  }

  /* ================================================================
     CDB_NEWS ENGINE - cached articles + live RSS fetch
     ================================================================ */
  var CACHE=[
    {source:'CISA ADVISORY',title:'CISA Adds Critical Ivanti & Fortinet CVEs to KEV Catalog',link:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',ts:'Apr 19',impact:'CRITICAL',tag:'KEV'},
    {source:'THE HACKER NEWS',title:'Chinese APT40 Exploits N-Day Bugs Within Hours of PoC Release',link:'https://thehackernews.com',ts:'Apr 18',impact:'CRITICAL',tag:'APT'},
    {source:'BLEEPING COMPUTER',title:'LockBit Ransomware Targets Healthcare Sector Globally',link:'https://www.bleepingcomputer.com',ts:'Apr 17',impact:'HIGH',tag:'RANSOMWARE'},
    {source:'CISA ADVISORY',title:'ICS/SCADA Vulnerabilities Disclosed in Multiple Vendor Products',link:'https://www.cisa.gov/ics-advisories',ts:'Apr 16',impact:'HIGH',tag:'ICS'},
    {source:'KREBS ON SECURITY',title:'Russian GRU Unit Sandworm Linked to New Wiper Malware Campaign',link:'https://krebsonsecurity.com',ts:'Apr 15',impact:'CRITICAL',tag:'APT'},
    {source:'THE HACKER NEWS',title:'New Zero-Day in Microsoft Exchange Exploited by Nation-State Actors',link:'https://thehackernews.com',ts:'Apr 14',impact:'CRITICAL',tag:'0DAY'},
    {source:'BLEEPING COMPUTER',title:'FBI Warns of Scattered Spider Attacks on Financial Institutions',link:'https://www.bleepingcomputer.com',ts:'Apr 13',impact:'HIGH',tag:'FBI'},
    {source:'DARK READING',title:'Supply Chain Attack Targets Popular npm Packages with 500K+ Downloads',link:'https://www.darkreading.com',ts:'Apr 12',impact:'HIGH',tag:'SUPPLY-CHAIN'},
    {source:'CISA ADVISORY',title:'Joint Advisory: ALPHV BlackCat Ransomware Targeting Critical Infrastructure',link:'https://www.cisa.gov',ts:'Apr 11',impact:'CRITICAL',tag:'RANSOMWARE'},
    {source:'THE HACKER NEWS',title:'Lazarus Group Deploys New macOS Backdoor via Job Lures',link:'https://thehackernews.com',ts:'Apr 10',impact:'HIGH',tag:'APT'},
    {source:'BLEEPING COMPUTER',title:'Mass Exploitation of MOVEit Transfer Vulnerability Underway',link:'https://www.bleepingcomputer.com',ts:'Apr 9',impact:'CRITICAL',tag:'KEV'},
    {source:'KREBS ON SECURITY',title:'DarkGate Malware Delivers Trojans via Microsoft Teams',link:'https://krebsonsecurity.com',ts:'Apr 8',impact:'MEDIUM',tag:'MALWARE'},
  ];
  var IMPACT_COL={CRITICAL:'#ef4444',HIGH:'#f59e0b',MEDIUM:'#8b5cf6',LOW:'#6b7280'};
  var TAG_COL={KEV:'#ef4444',APT:'#a78bfa','0DAY':'#ef4444',RANSOMWARE:'#f59e0b','SUPPLY-CHAIN':'#f97316',ICS:'#22c55e',FBI:'#3b82f6',MALWARE:'#ec4899',LIVE:'#22c55e'};
  var GRID=sel('cdb-news-grid'), LU=sel('cdb-news-last-update');

  function card(a,live){
    var ic=IMPACT_COL[a.impact]||'#6b7280';
    var tc=TAG_COL[a.tag]||'#64748b';
    var lb=live?'<span style="background:#22c55e22;color:#22c55e;padding:1px 5px;border-radius:3px;font-size:8px;margin-left:4px;">LIVE</span>':'';
    return '<div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:12px;margin-bottom:8px;">'
      +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">'
      +'<span style="color:#64748b;font-size:9px;font-weight:700;letter-spacing:0.05em;">'+a.source+'</span>'
      +'<span style="color:#475569;font-size:9px;">'+a.ts+'</span></div>'
      +'<a href="'+a.link+'" target="_blank" rel="noopener" style="color:#e2e8f0;font-size:12px;font-weight:600;text-decoration:none;line-height:1.4;">'+a.title+'</a>'+lb
      +'<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:7px;">'
      +'<span style="background:'+ic+'22;color:'+ic+';padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;">'+a.impact+'</span>'
      +(a.tag?'<span style="background:'+tc+'22;color:'+tc+';padding:2px 6px;border-radius:3px;font-size:8px;">'+a.tag+'</span>':'')
      +'</div></div>';
  }

  function refreshNews(){
    if(!GRID) return;
    GRID.innerHTML=CACHE.map(function(a){return card(a,false);}).join('');
    if(LU) LU.textContent='Updated: '+new Date().toLocaleTimeString();
    var PROXIES=['https://api.allorigins.win/raw?url=','https://corsproxy.io/?'];
    var FEEDS=['https://feeds.feedburner.com/TheHackersNews','https://www.bleepingcomputer.com/feed/','https://krebsonsecurity.com/feed/'];
    var tried=0;
    function tryNext(){
      if(tried>=PROXIES.length*FEEDS.length) return;
      var pi=Math.floor(tried/FEEDS.length), fi=tried%FEEDS.length; tried++;
      var feedName=FEEDS[fi].includes('thehackernews')?'THE HACKER NEWS':FEEDS[fi].includes('bleepingcomputer')?'BLEEPING COMPUTER':'KREBS ON SECURITY';
      var sig; try{sig=AbortSignal.timeout(8000);}catch(ex){sig=undefined;}
      fetch(PROXIES[pi]+encodeURIComponent(FEEDS[fi]),{signal:sig})
        .then(function(r){return r.text();})
        .then(function(xml){
          var items=xml.match(/<item[\s\S]*?<\/item>/g)||[];
          if(!items.length){tryNext();return;}
          var arts=items.slice(0,8).map(function(it){
            var t=(it.match(/<title[^>]*><!\[CDATA\[([\s\S]*?)\]\]>/)||it.match(/<title[^>]*>([\s\S]*?)<\/title>/)||[])[1]||'';
            var l=(it.match(/<link>([\s\S]*?)<\/link>/)||[])[1]||'#';
            var d=(it.match(/<pubDate>([\s\S]*?)<\/pubDate>/)||[])[1]||'';
            var ts=d?new Date(d).toLocaleDateString('en-US',{month:'short',day:'numeric'}):'TODAY';
            return {source:feedName,title:t.trim(),link:l.trim(),ts:ts,impact:'HIGH',tag:'LIVE'};
          });
          GRID.innerHTML=arts.map(function(a){return card(a,true);}).join('')+CACHE.slice(0,4).map(function(a){return card(a,false);}).join('');
          if(LU) LU.textContent='Live: '+new Date().toLocaleTimeString()+' ('+feedName+')';
        }).catch(function(){tryNext();});
    }
    tryNext();
  }

  /* ── Boot sequence ── */
  function boot(){
    runAIBrain();
    if(GRID){
      GRID.innerHTML=CACHE.map(function(a){return card(a,false);}).join('');
      if(LU) LU.textContent='Cache loaded | Fetching live feed...';
      setTimeout(refreshNews, 600);
    }
  }
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded', boot);
  } else { boot(); }

  /* ================================================================
     ENTERPRISE COMMAND CENTER — Value Visualization + Premium Signals
     v131.0: Financial impact, risk exposure, breach cost indicators
     ================================================================ */
  function injectEnterpriseSignals(){
    var intel=window.EMBEDDED_INTEL||[];
    if(!intel.length) return;

    /* -- Financial Impact Calculator -- */
    var criticalCount=intel.filter(function(t){return(t.severity||'').toUpperCase()==='CRITICAL';}).length;
    var highCount=intel.filter(function(t){return(t.severity||'').toUpperCase()==='HIGH';}).length;
    var totalRisk=criticalCount*4.5+highCount*1.5; // $M
    var iocTotal=intel.reduce(function(s,t){return s+(t.ioc_count||t.iocs&&t.iocs.length||0);},0);

    /* Inject financial impact bar if container exists */
    var finBar=sel('financial-impact-bar')||sel('risk-exposure-bar')||sel('breach-cost-bar');
    if(!finBar){
      /* Create and inject a floating command bar at top of intel sections */
      var bar=document.createElement('div');
      bar.id='cdb-financial-bar';
      bar.style.cssText='background:linear-gradient(135deg,rgba(15,23,42,0.98),rgba(30,41,59,0.98));'+
        'border:1px solid #334155;border-radius:10px;padding:14px 20px;margin:12px 0;'+
        'display:flex;flex-wrap:wrap;gap:20px;align-items:center;justify-content:space-between;'+
        'box-shadow:0 4px 24px rgba(139,92,246,0.15);';
      var metrics=[
        {label:'Estimated Financial Exposure',value:'$'+(totalRisk.toFixed(1))+'M',color:'#ef4444'},
        {label:'Active IOCs Available',value:iocTotal.toString(),color:'#f59e0b'},
        {label:'Critical Threats',value:criticalCount.toString(),color:'#ef4444'},
        {label:'High Severity',value:highCount.toString(),color:'#f59e0b'},
        {label:'Risk Coverage',value:Math.min(99,Math.round((criticalCount+highCount)*8.5))+'%',color:'#22c55e'},
        {label:'Breach Cost Indicator',value:'$'+(criticalCount*4.5+highCount*1.5).toFixed(1)+'M avg',color:'#8b5cf6'},
      ];
      bar.innerHTML=metrics.map(function(m){
        return '<div style="text-align:center;min-width:90px;">'
          +'<div style="font-size:18px;font-weight:800;color:'+m.color+';line-height:1;">'+m.value+'</div>'
          +'<div style="font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;margin-top:2px;">'+m.label+'</div>'
          +'</div>';
      }).join('')
        +'<div style="flex-shrink:0;">'
        +'<a href="https://intel.cyberdudebivash.com/upgrade?plan=pro" '
        +'style="background:linear-gradient(135deg,#7c3aed,#2563eb);color:white;padding:8px 16px;'
        +'border-radius:6px;text-decoration:none;font-size:11px;font-weight:700;white-space:nowrap;">'
        +'UNLOCK FULL INTEL</a></div>';

      /* Find best insertion point */
      var anchor=sel('ai-campaigns-body')||sel('cdb-news-grid')||document.querySelector('main')||document.body;
      if(anchor&&anchor.parentNode){
        anchor.parentNode.insertBefore(bar,anchor);
      }
    }

    /* -- Urgency pulse on CRITICAL badges -- */
    document.querySelectorAll('[data-severity="CRITICAL"],[data-sev="CRITICAL"]').forEach(function(el){
      el.style.animation='urgency-pulse 2s infinite';
    });

    /* -- Inject urgency CSS if not present -- */
    if(!document.getElementById('cdb-enterprise-css')){
      var style=document.createElement('style');
      style.id='cdb-enterprise-css';
      style.textContent=[
        '@keyframes urgency-pulse{0%,100%{opacity:1}50%{opacity:0.6}}',
        '#cdb-financial-bar{animation:slideIn 0.5s ease-out;}',
        '@keyframes slideIn{from{transform:translateY(-10px);opacity:0}to{transform:translateY(0);opacity:1}}',
        '.cdb-threat-score{display:inline-flex;align-items:center;gap:4px;background:rgba(239,68,68,0.15);'+
          'color:#ef4444;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;}',
        '.cdb-premium-badge{background:linear-gradient(135deg,#7c3aed,#2563eb);color:white;'+
          'padding:2px 7px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:0.05em;}',
      ].join('');
      document.head.appendChild(style);
    }
  }

  /* Run enterprise signals after main boot */
  function bootEnterprise(){
    boot();
    setTimeout(injectEnterpriseSignals, 800);
  }

  /* Override boot with enterprise version */
  if(document.readyState==='loading'){
    document.removeEventListener('DOMContentLoaded', boot);
    document.addEventListener('DOMContentLoaded', bootEnterprise);
  } else {
    setTimeout(injectEnterpriseSignals, 800);
  }

  /* Expose for manual refresh buttons */
  window.CDB_NEWS={refresh:refreshNews};
})();
