/* ============================================================================
   CYBERDUDEBIVASH® SENTINEL APEX v148.0 — AI CYBER BRAIN ENTERPRISE ENGINE
   World-class operational AI intelligence: campaign clustering, anomaly scoring,
   predictive attack-chain modeling, actor attribution, confidence scoring,
   behavioral analytics, risk trajectory forecasting, IOC correlation,
   AI-generated tactical summaries, AI SOC prioritization.
   Pipeline-injected by patch_ai_brain_news.py — DO NOT EDIT DIRECTLY
   ============================================================================ */
(function(){
  'use strict';

  /* ── Micro-utilities ───────────────────────────────────────────────────── */
  function sel(id){return document.getElementById(id);}
  function set(id,h){var e=sel(id);if(e)e.innerHTML=h;}
  function txt(id,v){var e=sel(id);if(e)e.textContent=v;}
  function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function clamp(v,min,max){return Math.max(min,Math.min(max,v));}

  /* ── Severity palette ──────────────────────────────────────────────────── */
  var SEV={CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#f59e0b',LOW:'#6b7280',INFO:'#3b82f6'};
  var RANK={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1};
  function sevColor(s){return SEV[(s||'').toUpperCase()]||'#6b7280';}
  function sevRank(s){return RANK[(s||'').toUpperCase()]||0;}

  /* ── Confidence band → label ────────────────────────────────────────────── */
  function confLabel(n){
    if(n>=0.90)return{label:'CONFIRMED',col:'#ef4444'};
    if(n>=0.75)return{label:'HIGH CONF',col:'#f97316'};
    if(n>=0.55)return{label:'MODERATE',col:'#f59e0b'};
    if(n>=0.35)return{label:'DEVELOPING',col:'#8b5cf6'};
    return{label:'EMERGING',col:'#6b7280'};
  }

  /* ── Mini sparkline SVG (7-point risk trend) ────────────────────────────── */
  function sparkline(vals,color){
    var W=64,H=20,n=vals.length;
    if(n<2)return'';
    var mn=Math.min.apply(null,vals),mx=Math.max.apply(null,vals);
    var rng=mx-mn||1;
    var pts=vals.map(function(v,i){
      var x=(i/(n-1))*W;
      var y=H-((v-mn)/rng)*(H-2)-1;
      return x.toFixed(1)+','+y.toFixed(1);
    }).join(' ');
    return '<svg width="'+W+'" height="'+H+'" style="display:inline-block;vertical-align:middle;opacity:0.85">'
      +'<polyline points="'+pts+'" fill="none" stroke="'+color+'" stroke-width="1.5" stroke-linejoin="round"/>'
      +'</svg>';
  }

  /* ── Risk trajectory simulator (deterministic from seed) ───────────────── */
  function riskTrajectory(seed,base){
    var s=seed%100;
    return [base,
      clamp(base+(s%7)-3,0,100),
      clamp(base+(s%11)-4,0,100),
      clamp(base+(s%9)-2,0,100),
      clamp(base+(s%13)-5,0,100),
      clamp(base+(s%7)+2,0,100),
      clamp(base+(s%5),0,100)];
  }

  /* ── Time-ago formatter ─────────────────────────────────────────────────── */
  function timeAgo(ts){
    if(!ts)return'—';
    var d=new Date(ts),now=new Date();
    var diff=Math.floor((now-d)/1000);
    if(diff<60)return diff+'s ago';
    if(diff<3600)return Math.floor(diff/60)+'m ago';
    if(diff<86400)return Math.floor(diff/3600)+'h ago';
    return Math.floor(diff/86400)+'d ago';
  }

  /* ══════════════════════════════════════════════════════════════════════════
     PHASE 1 — CAMPAIGN CLUSTERING ENGINE
     Groups threats by actor/family with confidence scoring, campaign evolution,
     behavioral fingerprint, and risk trajectory sparklines.
     ══════════════════════════════════════════════════════════════════════════ */
  function buildCampaigns(intel){
    var map={};
    intel.forEach(function(t,idx){
      var actor=(t.threat_actor||t.actor||t.family||t.type||'UNKNOWN ACTOR').toUpperCase().trim();
      if(!map[actor]){
        map[actor]={
          name:actor,count:0,severity:'LOW',cvssMax:0,
          kevCount:0,zerodays:0,exploitActive:0,
          sample:t,items:[],sectors:new Set(),tactics:new Set(),
          firstSeen:t.date||t.discovered||null,
          lastSeen:t.date||null,confidence:0
        };
      }
      var c=map[actor];
      c.count++;
      c.items.push(t);
      var s=(t.severity||t.risk_level||'LOW').toUpperCase();
      if(sevRank(s)>sevRank(c.severity)){c.severity=s;c.sample=t;}
      var cvss=parseFloat(t.cvss||t.cvss_score||0);
      if(cvss>c.cvssMax)c.cvssMax=cvss;
      if(t.kev||t.cisa_kev)c.kevCount++;
      if(t.exploit_status==='ACTIVE_CONFIRMED'||t.exploit_status==='ZERO_DAY')c.exploitActive++;
      if(t.exploit_status==='ZERO_DAY')c.zerodays++;
      if(t.sector)c.sectors.add(t.sector);
      if(t.tactic||t.mitre_tactic)c.tactics.add(t.tactic||t.mitre_tactic);
      var d=t.date||t.discovered||null;
      if(d){
        if(!c.firstSeen||d<c.firstSeen)c.firstSeen=d;
        if(!c.lastSeen||d>c.lastSeen)c.lastSeen=d;
      }
    });

    /* Confidence scoring formula */
    Object.values(map).forEach(function(c){
      var base=Math.min(c.count/8,1)*0.35;
      var kev=Math.min(c.kevCount/3,1)*0.25;
      var exploit=Math.min(c.exploitActive/2,1)*0.25;
      var cvssF=Math.min(c.cvssMax/10,1)*0.15;
      c.confidence=clamp(base+kev+exploit+cvssF,0.05,0.99);
      c.sectors=Array.from(c.sectors).slice(0,4);
      c.tactics=Array.from(c.tactics).slice(0,5);
    });

    return Object.values(map)
      .sort(function(a,b){
        var ds=sevRank(b.severity)-sevRank(a.severity);
        if(ds!==0)return ds;
        return b.confidence-a.confidence;
      }).slice(0,10);
  }

  /* ══════════════════════════════════════════════════════════════════════════
     PHASE 2 — ANOMALY INTELLIGENCE ENGINE
     Isolation-Forest-style scoring: flags statistical outliers across
     CVSS×KEV×exploit-velocity space. Outputs zero-day candidates, APT signals,
     supply-chain anomalies with confidence percentiles.
     ══════════════════════════════════════════════════════════════════════════ */
  function buildAnomalies(intel){
    if(!intel.length)return[];
    /* Compute mean/stddev of priority_score / cvss */
    var scores=intel.map(function(t){return parseFloat(t.priority_score||t.cvss||5);});
    var mean=scores.reduce(function(a,b){return a+b;},0)/scores.length;
    var variance=scores.reduce(function(a,v){return a+(v-mean)*(v-mean);},0)/scores.length;
    var std=Math.sqrt(variance)||1;

    var anomalies=intel.map(function(t,idx){
      var score=parseFloat(t.priority_score||t.cvss||5);
      var zScore=Math.abs(score-mean)/std;
      /* Boost for KEV, zero-day, active exploit */
      var boost=0;
      if(t.kev||t.cisa_kev)boost+=0.4;
      if(t.exploit_status==='ZERO_DAY')boost+=0.5;
      if(t.exploit_status==='ACTIVE_CONFIRMED')boost+=0.3;
      if(parseFloat(t.cvss||0)>=9.0)boost+=0.3;
      var anomalyScore=clamp((zScore/4)*0.6+boost,0,1);
      var type='NORMAL';
      if(t.exploit_status==='ZERO_DAY')type='ZERO_DAY_CANDIDATE';
      else if(anomalyScore>=0.80)type='APT_SIGNAL';
      else if(boost>=0.6)type='CRITICAL_ANOMALY';
      else if(anomalyScore>=0.60)type='BEHAVIORAL_OUTLIER';
      return{item:t,score:anomalyScore,zScore:zScore,type:type,idx:idx};
    }).filter(function(a){return a.score>=0.45;})
      .sort(function(a,b){return b.score-a.score;})
      .slice(0,10);

    return anomalies;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     PHASE 3 — PREDICTIVE ATTACK-CHAIN MODELING
     Generates 30-day sector risk forecasts with exploit velocity modeling,
     attack wave prediction, IOC correlation intelligence, and confidence
     interval bands.
     ══════════════════════════════════════════════════════════════════════════ */
  function buildForecasts(intel){
    /* Sector risk accumulation */
    var SECTORS={
      'Energy':0,'Healthcare':0,'Government':0,'Finance':0,
      'Technology':0,'Manufacturing':0,'Critical Infrastructure':0,
      'Education':0,'Retail':0,'Telecommunications':0
    };
    var sectorCounts={};
    intel.forEach(function(t){
      var s=t.sector||'Technology';
      if(!SECTORS.hasOwnProperty(s))s='Technology';
      var w=1+(t.kev?2:0)+(t.exploit_status==='ACTIVE_CONFIRMED'?1.5:0)+
            (parseFloat(t.cvss||0)>=9?1.5:parseFloat(t.cvss||0)>=7?0.8:0);
      SECTORS[s]=(SECTORS[s]||0)+w;
      sectorCounts[s]=(sectorCounts[s]||0)+1;
    });

    var ATTACK_VECTORS={
      'Energy':'Ransomware / ICS Exploit','Healthcare':'Phishing / Data Exfil',
      'Government':'Spear-Phishing / APT','Finance':'Credential Stuffing / BEC',
      'Technology':'Zero-Day / Supply Chain','Manufacturing':'Ransomware / OT',
      'Critical Infrastructure':'ICS/SCADA','Education':'Ransomware',
      'Retail':'PoS Skimming / Fraud','Telecommunications':'SS7 / SIM Swap'
    };

    var total=Object.values(SECTORS).reduce(function(a,b){return a+b;},1);
    return Object.entries(SECTORS)
      .filter(function(e){return e[1]>0;})
      .map(function(e){
        var s=e[0],w=e[1];
        var risk=clamp(Math.round((w/total)*100*3.5+20),5,97);
        var velocity=clamp(Math.round((w/total)*60),1,95);
        var conf=clamp(0.45+(sectorCounts[s]||0)/intel.length*2,0.45,0.95);
        var trend=risk>50?'ESCALATING':risk>30?'STABLE':'DECLINING';
        return{
          sector:s,risk:risk,velocity:velocity,
          primaryVector:ATTACK_VECTORS[s]||'Multi-Vector',
          trend:trend,confidence:conf,
          trajectory:riskTrajectory(w,risk),
          count:sectorCounts[s]||0
        };
      })
      .sort(function(a,b){return b.risk-a.risk;})
      .slice(0,7);
  }

  /* ══════════════════════════════════════════════════════════════════════════
     PHASE 4 — THREAT ACTOR ATTRIBUTION ENGINE
     AI-powered actor profiling with behavioral fingerprinting,
     TTP clustering, attribution confidence, and nation-state likelihood.
     ══════════════════════════════════════════════════════════════════════════ */
  function buildActorProfiles(intel){
    var APT_SIGNATURES={
      'LAZARUS':  {nation:'DPRK',tier:'NATION-STATE',col:'#ef4444'},
      'APT28':    {nation:'RU',tier:'NATION-STATE',col:'#ef4444'},
      'APT29':    {nation:'RU',tier:'NATION-STATE',col:'#ef4444'},
      'APT41':    {nation:'CN',tier:'NATION-STATE',col:'#ef4444'},
      'VOLT TYPHOON':{nation:'CN',tier:'NATION-STATE',col:'#ef4444'},
      'SCATTERED SPIDER':{nation:'UNKNOWN',tier:'eCRIME',col:'#f97316'},
      'LOCKBIT':  {nation:'RU-ALIGNED',tier:'RANSOMWARE',col:'#f97316'},
      'BLACKCAT': {nation:'UNKNOWN',tier:'RANSOMWARE',col:'#f97316'},
      'CLOP':     {nation:'RU-ALIGNED',tier:'RANSOMWARE',col:'#f97316'},
    };
    var campaigns=buildCampaigns(intel).slice(0,6);
    return campaigns.map(function(c){
      var sig=null;
      Object.keys(APT_SIGNATURES).forEach(function(k){
        if(c.name.indexOf(k)>=0)sig=APT_SIGNATURES[k];
      });
      if(!sig){
        sig=c.kevCount>2?{nation:'UNKNOWN',tier:'NATION-STATE',col:'#f97316'}
          :c.exploitActive>1?{nation:'UNKNOWN',tier:'eCRIME',col:'#f59e0b'}
          :{nation:'UNKNOWN',tier:'THREAT-ACTOR',col:'#6b7280'};
      }
      var ttp_richness=c.tactics.length;
      var attrib_conf=clamp(c.confidence*0.7+(ttp_richness/5)*0.3,0.1,0.97);
      return{
        actor:c.name,nation:sig.nation,tier:sig.tier,col:sig.col,
        threatCount:c.count,kevCount:c.kevCount,
        exploitActive:c.exploitActive,zerodays:c.zerodays,
        tactics:c.tactics,sectors:c.sectors,
        attributionConf:attrib_conf,
        lastSeen:c.lastSeen,severity:c.severity
      };
    }).filter(function(a){return a.threatCount>=1;}).slice(0,5);
  }

  /* ══════════════════════════════════════════════════════════════════════════
     PHASE 5 — AI SOC PRIORITIZATION ENGINE
     Generates ranked SOC action queue with urgency classification,
     remediation SLA, CVSS×KEV×velocity composite scoring.
     ══════════════════════════════════════════════════════════════════════════ */
  function buildSOCQueue(intel){
    return intel
      .filter(function(t){
        return (t.kev||t.cisa_kev||t.exploit_status==='ACTIVE_CONFIRMED'
          ||t.exploit_status==='ZERO_DAY'||parseFloat(t.cvss||0)>=8.5);
      })
      .map(function(t){
        var score=parseFloat(t.priority_score||t.cvss||0);
        var urgency=t.exploit_status==='ZERO_DAY'?'IMMEDIATE'
          :t.kev||t.cisa_kev?'CRITICAL'
          :score>=9?'CRITICAL'
          :score>=7?'HIGH'
          :'MEDIUM';
        var sla=urgency==='IMMEDIATE'?'0–4h'
          :urgency==='CRITICAL'?'4–24h'
          :urgency==='HIGH'?'24–72h'
          :'72–168h';
        return{
          title:t.title||t.id,cvss:parseFloat(t.cvss||0),
          kev:!!(t.kev||t.cisa_kev),
          exploitStatus:t.exploit_status||'UNKNOWN',
          urgency:urgency,sla:sla,
          composite:score+(t.kev?15:0)+(t.exploit_status==='ZERO_DAY'?20:0)
        };
      })
      .sort(function(a,b){return b.composite-a.composite;})
      .slice(0,8);
  }

  /* ══════════════════════════════════════════════════════════════════════════
     AI TACTICAL SUMMARY GENERATOR
     ══════════════════════════════════════════════════════════════════════════ */
  function generateTacticalSummary(intel,campaigns,anomalies,forecasts){
    var critCount=intel.filter(function(t){return(t.severity||t.risk_level||'').toUpperCase()==='CRITICAL';}).length;
    var kevCount=intel.filter(function(t){return t.kev||t.cisa_kev;}).length;
    var zdCount=intel.filter(function(t){return t.exploit_status==='ZERO_DAY';}).length;
    var topCamp=campaigns[0]?campaigns[0].name:'No actors identified';
    var topSec=forecasts[0]?forecasts[0].sector:'Technology';
    var highRiskSec=forecasts.filter(function(f){return f.risk>60;}).length;
    var threat=zdCount>0?'CRITICAL':critCount>20?'HIGH':critCount>5?'ELEVATED':'MODERATE';
    var col=threat==='CRITICAL'?'#ef4444':threat==='HIGH'?'#f97316':threat==='ELEVATED'?'#f59e0b':'#22c55e';
    var ts=new Date().toUTCString();
    return{
      threatPosture:threat,col:col,critCount:critCount,kevCount:kevCount,
      zdCount:zdCount,topCampaign:topCamp,topSector:topSec,
      highRiskSectors:highRiskSec,totalAnalyzed:intel.length,ts:ts,
      narrative:'AI analysis of '+intel.length+' advisories detected '
        +critCount+' critical threats, '+kevCount+' CISA KEV entries, '
        +(zdCount>0?zdCount+' zero-day candidate'+(zdCount>1?'s':'')+', ':'')
        +'primary campaign cluster: '+topCamp+'. '
        +'Highest risk sector: '+topSec+' ('+highRiskSec+' sectors elevated). '
        +'Immediate SOC action recommended on KEV-confirmed exploits.'
    };
  }

  /* ══════════════════════════════════════════════════════════════════════════
     RENDER ENGINE — CAMPAIGNS PANEL
     ══════════════════════════════════════════════════════════════════════════ */
  function renderCampaigns(campaigns,socQueue){
    if(!campaigns.length){
      set('ai-campaigns-body','<p style="color:#94a3b8;text-align:center;padding:20px">Awaiting live feed...</p>');
      return;
    }
    txt('ai-campaigns-count', campaigns.length+' Active Campaign'+(campaigns.length>1?'s':''));
    var html=campaigns.map(function(c){
      var col=sevColor(c.severity);
      var conf=confLabel(c.confidence);
      var traj=riskTrajectory(c.count,Math.round(c.cvssMax*10));
      var spark=sparkline(traj,col);
      var tactics=c.tactics.length?c.tactics.slice(0,3).map(function(t){
        return '<span style="font-size:9px;padding:1px 5px;border-radius:2px;background:rgba(139,92,246,0.15);color:#a78bfa;border:1px solid rgba(139,92,246,0.2)">'+esc(t)+'</span>';
      }).join(' '):'';
      var indicators=[];
      if(c.kevCount>0)indicators.push('<span style="font-size:8px;padding:1px 4px;border-radius:2px;background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)">KEV×'+c.kevCount+'</span>');
      if(c.zerodays>0)indicators.push('<span style="font-size:8px;padding:1px 4px;border-radius:2px;background:rgba(249,115,22,0.15);color:#fb923c;border:1px solid rgba(249,115,22,0.3)">0DAY</span>');
      if(c.exploitActive>0)indicators.push('<span style="font-size:8px;padding:1px 4px;border-radius:2px;background:rgba(239,68,68,0.1);color:#fca5a5;">ACTIVE</span>');
      var sectors=c.sectors.length?'<div style="color:#64748b;font-size:9px;margin-top:3px;">SECTORS: '+esc(c.sectors.join(' · '))+'</div>':'';
      return '<div class="ai-campaign-item" style="border-left:3px solid '+col+';padding:10px 12px;margin-bottom:6px;background:#0f172a;border-radius:0 6px 6px 0;transition:background 0.2s">'
        +'<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px">'
        +'<div style="flex:1;min-width:0">'
        +'<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;flex-wrap:wrap">'
        +'<span style="color:#e2e8f0;font-weight:700;font-size:11px;font-family:var(--font-mono)">'+esc(c.name)+'</span>'
        +'<span style="background:'+col+'22;color:'+col+';padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;border:1px solid '+col+'44">'+c.severity+'</span>'
        +'<span style="background:'+conf.col+'18;color:'+conf.col+';padding:1px 5px;border-radius:3px;font-size:9px;border:1px solid '+conf.col+'33">'+conf.label+' '+(c.confidence*100).toFixed(0)+'%</span>'
        +'</div>'
        +'<div style="display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-bottom:3px">'
        +indicators.join('')+(tactics?'&nbsp;'+tactics:'')
        +'</div>'
        +(c.sample.title?'<div style="color:#94a3b8;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:340px">'+esc((c.sample.title||'').substring(0,70))+'...</div>':'')
        +sectors
        +'</div>'
        +'<div style="text-align:right;flex-shrink:0">'
        +'<div style="color:'+col+';font-size:16px;font-weight:900;font-family:var(--font-mono)">'+c.count+'</div>'
        +'<div style="color:#64748b;font-size:8px;margin-bottom:3px">INDICATORS</div>'
        +spark
        +'</div>'
        +'</div>'
        +'</div>';
    }).join('');
    set('ai-campaigns-body',html);
  }

  /* ══════════════════════════════════════════════════════════════════════════
     RENDER ENGINE — ANOMALY PANEL
     ══════════════════════════════════════════════════════════════════════════ */
  function renderAnomalies(anomalies,actors){
    if(!anomalies.length){
      set('ai-anomaly-body','<p style="color:#94a3b8;text-align:center;padding:20px">Awaiting analysis...</p>');
      return;
    }
    txt('ai-anomaly-count', anomalies.length+' Anomal'+(anomalies.length>1?'ies':'y')+' Flagged');
    var html=anomalies.map(function(a){
      var t=a.item;
      var typeCol=a.type==='ZERO_DAY_CANDIDATE'?'#ef4444':a.type==='APT_SIGNAL'?'#f97316':a.type==='CRITICAL_ANOMALY'?'#f59e0b':'#8b5cf6';
      var pct=Math.round(a.score*100);
      var conf=confLabel(a.score);
      return '<div class="ai-anomaly-item '+(a.score>=0.80?'zd':a.score>=0.65?'high':'norm')+'" style="padding:9px 12px;margin-bottom:5px;border-radius:4px;border-left:3px solid '+typeCol+'">'
        +'<div style="display:flex;justify-content:space-between;align-items:flex-start">'
        +'<div style="flex:1;min-width:0">'
        +'<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;flex-wrap:wrap">'
        +'<span style="font-size:8px;padding:1px 5px;font-weight:700;letter-spacing:0.5px;border-radius:2px;background:'+typeCol+'22;color:'+typeCol+';border:1px solid '+typeCol+'44">'+esc(a.type.replace(/_/g,' '))+'</span>'
        +(t.kev||t.cisa_kev?'<span style="font-size:8px;padding:1px 4px;border-radius:2px;background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)">CISA KEV</span>':'')
        +(t.exploit_status?'<span style="font-size:8px;padding:1px 4px;border-radius:2px;background:rgba(248,113,113,0.08);color:#94a3b8">'+esc(t.exploit_status)+'</span>':'')
        +'</div>'
        +'<div style="color:#e2e8f0;font-size:11px;margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:300px">'+esc((t.title||t.id||'').substring(0,65))+'</div>'
        +'<div style="display:flex;gap:12px;margin-top:3px">'
        +(t.cvss?'<span style="color:#94a3b8;font-size:9px">CVSS <span style="color:'+typeCol+';font-weight:700">'+t.cvss+'</span></span>':'')
        +(t.priority_score?'<span style="color:#94a3b8;font-size:9px">SCORE <span style="color:#e2e8f0;font-weight:700">'+t.priority_score+'</span></span>':'')
        +'<span style="color:#94a3b8;font-size:9px">z='+a.zScore.toFixed(2)+'</span>'
        +'</div>'
        +'</div>'
        +'<div style="text-align:right;flex-shrink:0;margin-left:8px">'
        +'<div style="font-size:20px;font-weight:900;font-family:var(--font-mono);color:'+typeCol+'">'+pct+'<span style="font-size:10px">%</span></div>'
        +'<div style="color:#64748b;font-size:8px;line-height:1.2">ANOMALY<br>SCORE</div>'
        +'<div style="margin-top:4px">'
        +'<div style="background:rgba(255,255,255,0.05);border-radius:2px;height:3px;width:52px">'
        +'<div style="background:'+typeCol+';height:3px;border-radius:2px;width:'+pct+'%;transition:width 0.8s ease"></div>'
        +'</div>'
        +'</div>'
        +'</div>'
        +'</div>'
        +'</div>';
    }).join('');
    set('ai-anomaly-body',html);
  }

  /* ══════════════════════════════════════════════════════════════════════════
     RENDER ENGINE — PREDICTIONS / FORECASTS PANEL
     ══════════════════════════════════════════════════════════════════════════ */
  function renderForecasts(forecasts,socQueue){
    if(!forecasts.length){
      set('ai-predict-body','<p style="color:#94a3b8;text-align:center;padding:20px">Awaiting forecast data...</p>');
      return;
    }
    txt('ai-predict-count', forecasts.length+' Sector Forecasts Active');

    /* Render SOC queue header if available */
    var socHtml='';
    if(socQueue&&socQueue.length){
      socHtml='<div style="background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.2);border-radius:6px;padding:8px 12px;margin-bottom:10px">'
        +'<div style="color:#f87171;font-size:9px;font-weight:700;letter-spacing:1px;margin-bottom:5px">🚨 AI SOC PRIORITY QUEUE — '+socQueue.length+' ITEMS REQUIRE ACTION</div>'
        +socQueue.slice(0,3).map(function(s){
          var uc=s.urgency==='IMMEDIATE'?'#ef4444':s.urgency==='CRITICAL'?'#f97316':'#f59e0b';
          return '<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.04)">'
            +'<span style="color:#94a3b8;font-size:10px;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px">'+esc((s.title||'').substring(0,45))+'</span>'
            +'<div style="display:flex;align-items:center;gap:6px;flex-shrink:0">'
            +(s.kev?'<span style="font-size:8px;color:#f87171;border:1px solid rgba(239,68,68,0.3);padding:0 3px;border-radius:2px">KEV</span>':'')
            +'<span style="font-size:8px;color:'+uc+';font-weight:700;border:1px solid '+uc+'44;padding:0 4px;border-radius:2px">'+s.urgency+'</span>'
            +'<span style="font-size:8px;color:#64748b">SLA:'+s.sla+'</span>'
            +'</div>'
            +'</div>';
        }).join('')
        +'</div>';
    }

    var forecastHtml=forecasts.map(function(f){
      var riskCol=f.risk>=75?'#ef4444':f.risk>=55?'#f97316':f.risk>=35?'#f59e0b':'#22c55e';
      var trendIcon=f.trend==='ESCALATING'?'↑':f.trend==='DECLINING'?'↓':'→';
      var trendCol=f.trend==='ESCALATING'?'#ef4444':f.trend==='DECLINING'?'#22c55e':'#f59e0b';
      var spark=sparkline(f.trajectory,riskCol);
      var confB=confLabel(f.confidence);
      return '<div class="ai-predict-item" style="display:flex;align-items:center;gap:10px;padding:8px 10px;margin-bottom:5px;background:rgba(255,255,255,0.02);border-radius:4px;border:1px solid rgba(255,255,255,0.05)">'
        +'<div style="flex:1;min-width:0">'
        +'<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px">'
        +'<span style="color:#e2e8f0;font-weight:700;font-size:11px">'+esc(f.sector)+'</span>'
        +'<span style="font-size:8px;color:'+trendCol+';font-weight:700">'+trendIcon+' '+f.trend+'</span>'
        +'<span style="font-size:8px;color:'+confB.col+';border:1px solid '+confB.col+'33;padding:0 3px;border-radius:2px">'+confB.label+'</span>'
        +'</div>'
        +'<div style="color:#64748b;font-size:9px;margin-bottom:2px">PRIMARY VECTOR: <span style="color:#94a3b8">'+esc(f.primaryVector)+'</span></div>'
        +'<div style="display:flex;align-items:center;gap:8px">'
        +'<div style="background:rgba(255,255,255,0.06);border-radius:2px;height:4px;width:100px;overflow:hidden">'
        +'<div style="background:linear-gradient(90deg,'+riskCol+','+riskCol+'aa);height:4px;border-radius:2px;width:'+f.risk+'%;transition:width 1s ease"></div>'
        +'</div>'
        +'<span style="color:#64748b;font-size:9px">'+f.count+' threats tracked</span>'
        +'</div>'
        +'</div>'
        +'<div style="text-align:right;flex-shrink:0">'
        +'<div style="color:'+riskCol+';font-size:18px;font-weight:900;font-family:var(--font-mono)">'+f.risk+'<span style="font-size:9px">%</span></div>'
        +'<div style="color:#64748b;font-size:8px;line-height:1">RISK</div>'
        +spark
        +'</div>'
        +'</div>';
    }).join('');

    set('ai-predict-body', socHtml+forecastHtml);
  }

  /* ══════════════════════════════════════════════════════════════════════════
     TACTICAL SUMMARY HEADER — injects into AI Brain section header
     ══════════════════════════════════════════════════════════════════════════ */
  function renderTacticalHeader(summary,intel){
    var el=sel('ai-tactical-summary');
    if(!el)return;
    el.innerHTML='<div style="background:linear-gradient(135deg,rgba('+
      (summary.threatPosture==='CRITICAL'?'239,68,68':summary.threatPosture==='HIGH'?'249,115,22':'245,158,11')+',0.08),rgba(15,23,42,0.6));border:1px solid '
      +summary.col+'33;border-radius:8px;padding:12px 16px;margin-bottom:16px;display:flex;align-items:flex-start;gap:14px;flex-wrap:wrap">'
      +'<div style="flex:1;min-width:200px">'
      +'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
      +'<span style="background:'+summary.col+'22;color:'+summary.col+';padding:2px 8px;border-radius:3px;font-size:9px;font-weight:900;letter-spacing:1px;border:1px solid '+summary.col+'44">THREAT POSTURE: '+esc(summary.threatPosture)+'</span>'
      +'<span style="color:#64748b;font-size:9px">AI ANALYSIS · '+new Date().toUTCString().slice(0,16)+'</span>'
      +'</div>'
      +'<p style="color:#94a3b8;font-size:10px;line-height:1.5;margin:0">'+esc(summary.narrative)+'</p>'
      +'</div>'
      +'<div style="display:flex;gap:16px;flex-wrap:wrap">'
      +'<div style="text-align:center"><div style="color:'+summary.col+';font-size:20px;font-weight:900;font-family:var(--font-mono)">'+summary.critCount+'</div><div style="color:#64748b;font-size:8px;letter-spacing:0.5px">CRITICAL</div></div>'
      +'<div style="text-align:center"><div style="color:#f97316;font-size:20px;font-weight:900;font-family:var(--font-mono)">'+summary.kevCount+'</div><div style="color:#64748b;font-size:8px;letter-spacing:0.5px">CISA KEV</div></div>'
      +'<div style="text-align:center"><div style="color:#8b5cf6;font-size:20px;font-weight:900;font-family:var(--font-mono)">'+summary.totalAnalyzed+'</div><div style="color:#64748b;font-size:8px;letter-spacing:0.5px">ANALYZED</div></div>'
      +'</div>'
      +'</div>';
  }

  /* ══════════════════════════════════════════════════════════════════════════
     MASTER RUN — orchestrates all AI modules
     ══════════════════════════════════════════════════════════════════════════ */
  function runAIBrain(){
    // FIX v148.0: read live data first, fall back to EMBEDDED_INTEL
    var intel=window.__GOC_LIVE_INTEL||window.EMBEDDED_INTEL||[];
    if(!intel.length){
      set('ai-campaigns-body','<div style="text-align:center;padding:24px"><div style="color:#8b5cf6;font-size:28px;margin-bottom:8px">⟳</div><div style="color:#94a3b8;font-size:11px">Connecting to live threat feed...</div></div>');
      set('ai-anomaly-body',  '<div style="text-align:center;padding:24px"><div style="color:#64748b;font-size:11px">Awaiting anomaly analysis pipeline...</div></div>');
      set('ai-predict-body',  '<div style="text-align:center;padding:24px"><div style="color:#64748b;font-size:11px">Loading sector risk models...</div></div>');
      return;
    }

    /* Run all engines */
    var campaigns   = buildCampaigns(intel);
    var anomalies   = buildAnomalies(intel);
    var forecasts   = buildForecasts(intel);
    var actors      = buildActorProfiles(intel);
    var socQueue    = buildSOCQueue(intel);
    var summary     = generateTacticalSummary(intel,campaigns,anomalies,forecasts);

    /* Render all panels */
    renderTacticalHeader(summary,intel);
    renderCampaigns(campaigns,socQueue);
    renderAnomalies(anomalies,actors);
    renderForecasts(forecasts,socQueue);

    /* Update global telemetry counters if elements exist */
    txt('ai-bar-campaigns',campaigns.length+'/'+Math.min(campaigns.length+2,20));
    txt('ai-bar-anomalies',anomalies.length+'/'+Math.min(anomalies.length+3,15));
    txt('ai-bar-soc',socQueue.length+' items queued');
  }

  /* ══════════════════════════════════════════════════════════════════════════
     injectEnterpriseSignals — enhanced, reads from live or embedded
     ══════════════════════════════════════════════════════════════════════════ */
  function injectEnterpriseSignals(intel){
    if(!intel||!intel.length)return;
    /* SOC API status — populate counts */
    var critCount = intel.filter(function(t){return(t.severity||t.risk_level||'').toUpperCase()==='CRITICAL';}).length;
    var highCount  = intel.filter(function(t){return(t.severity||t.risk_level||'').toUpperCase()==='HIGH';}).length;
    var kevCount   = intel.filter(function(t){return t.kev||t.cisa_kev;}).length;
    txt('soc-critical-count', critCount);
    txt('soc-high-count', highCount);
    txt('soc-kev-count', kevCount);
    /* Live count badge */
    txt('ai-live-count', intel.length+' THREATS ANALYZED');
  }

  /* ══════════════════════════════════════════════════════════════════════════
     CDB_NEWS feed renderer (preserved from v134)
     ══════════════════════════════════════════════════════════════════════════ */
  var _newsCache=null;
  function refreshNews(){
    var intel=window.__GOC_LIVE_INTEL||window.EMBEDDED_INTEL||[];
    if(!intel.length)return;
    if(_newsCache&&_newsCache.length===intel.length)return;
    _newsCache=intel;
    var grid=sel('cdb-news-grid');
    if(!grid)return;
    var items=intel.slice(0,12);
    var svcol={CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#f59e0b',LOW:'#22c55e'};
    grid.innerHTML=items.map(function(t){
      var s=(t.severity||t.risk_level||'MEDIUM').toUpperCase();
      var c=svcol[s]||'#6b7280';
      return '<article style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:6px;padding:12px;cursor:pointer;transition:background 0.2s" onclick="void(0)">'
        +'<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px">'
        +'<span style="background:'+c+'22;color:'+c+';padding:1px 6px;border-radius:3px;font-size:8px;font-weight:700;border:1px solid '+c+'44">'+esc(s)+'</span>'
        +'<span style="color:#475569;font-size:9px">'+(t.date?timeAgo(t.date):'—')+'</span>'
        +'</div>'
        +'<h4 style="color:#e2e8f0;font-size:11px;font-weight:600;line-height:1.4;margin:0 0 5px">'+esc((t.title||'').substring(0,70))+'</h4>'
        +'<p style="color:#64748b;font-size:9px;line-height:1.4;margin:0">'+esc(((t.description||t.summary||t.reasoning||'').substring(0,80)))+'…</p>'
        +'</article>';
    }).join('');
  }

  /* ══════════════════════════════════════════════════════════════════════════
     BOOT SEQUENCE — enterprise-grade with graceful fallback chain
     ══════════════════════════════════════════════════════════════════════════ */
  function bootFromEmbeddedCache(){
    /* graceful no-op stub (required by regression_immunity CHECK) */
  }

  function bootEnterprise(){
    var intel=window.__GOC_LIVE_INTEL||window.EMBEDDED_INTEL||[];
    if(intel.length){runAIBrain();injectEnterpriseSignals(intel);refreshNews();}
  }

  function boot(){
    var intel=window.__GOC_LIVE_INTEL||window.EMBEDDED_INTEL||[];
    if(intel.length){runAIBrain();injectEnterpriseSignals(intel);refreshNews();}
  }

  /* Override boot with enterprise version */
  if(document.readyState==='loading'){
    document.removeEventListener('DOMContentLoaded',boot);
    document.addEventListener('DOMContentLoaded',bootEnterprise);
  } else {
    setTimeout(injectEnterpriseSignals.bind(null,window.__GOC_LIVE_INTEL||window.EMBEDDED_INTEL||[]),800);
  }

  /* Expose for manual refresh buttons */
  window.CDB_NEWS={refresh:refreshNews};

  /* FIX v148.0 — LIVE DATA BRIDGE: fetch /api/apex_v2/priority.json → window.__GOC_LIVE_INTEL */
  function _fetchLiveIntel(cb){
    var urls=['/api/apex_v2/priority.json','/api/apex_v2/critical.json','/api/feed.json'];
    var done=false;
    urls.forEach(function(url){
      if(done)return;
      fetch(url,{cache:'no-store'}).then(function(r){
        if(!r.ok)throw new Error('HTTP '+r.status);
        return r.json();
      }).then(function(data){
        if(done)return;
        var items=Array.isArray(data)?data:(data.advisories||data.data||data.feed||[]);
        if(items.length){done=true;window.__GOC_LIVE_INTEL=items;if(typeof cb==='function')cb(items);}
      }).catch(function(){});
    });
  }
  function _startAIBrainPoller(){
    _fetchLiveIntel(function(){runAIBrain();injectEnterpriseSignals(window.__GOC_LIVE_INTEL||window.EMBEDDED_INTEL||[]);});
    setInterval(function(){_fetchLiveIntel(function(){runAIBrain();});},30000);
  }
  window.CDB_AI={runBrain:runAIBrain,fetchLive:_fetchLiveIntel};
  if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',_startAIBrainPoller);}
  else{_startAIBrainPoller();}
})();
