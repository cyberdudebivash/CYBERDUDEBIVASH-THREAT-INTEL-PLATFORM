
          /* ── ATTACK ORIGIN/TARGET NODES with lat/lon ── */
          var NODES=[
            {id:'US',n:'USA',ln:-98,lt:38},{id:'RU',n:'Russia',ln:60,lt:55},
            {id:'CN',n:'China',ln:116,lt:39},{id:'DE',n:'Germany',ln:10,lt:51},
            {id:'BR',n:'Brazil',ln:-47,lt:-15},{id:'IN',n:'India',ln:78,lt:22},
            {id:'GB',n:'UK',ln:-1,lt:52},{id:'FR',n:'France',ln:2,lt:47},
            {id:'JP',n:'Japan',ln:139,lt:35},{id:'AU',n:'Australia',ln:149,lt:-33},
            {id:'KR',n:'S.Korea',ln:127,lt:37},{id:'IR',n:'Iran',ln:51,lt:35},
            {id:'KP',n:'N.Korea',ln:125,lt:39},{id:'CA',n:'Canada',ln:-75,lt:45},
            {id:'MX',n:'Mexico',ln:-99,lt:19},{id:'UA',n:'Ukraine',ln:30,lt:50},
            {id:'IL',n:'Israel',ln:35,lt:31},{id:'SA',n:'Saudi',ln:46,lt:24},
            {id:'NG',n:'Nigeria',ln:7,lt:6},{id:'ZA',n:'S.Africa',ln:25,lt:-29},
            {id:'PK',n:'Pakistan',ln:74,lt:30},{id:'TH',n:'Thailand',ln:101,lt:14},
            {id:'ID',n:'Indonesia',ln:107,lt:-6},{id:'TR',n:'Turkey',ln:32,lt:39},
            {id:'IT',n:'Italy',ln:12,lt:42},{id:'ES',n:'Spain',ln:-4,lt:40},
            {id:'PL',n:'Poland',ln:21,lt:52},{id:'NL',n:'Netherlands',ln:5,lt:52},
            {id:'VN',n:'Vietnam',ln:106,lt:16},{id:'MY',n:'Malaysia',ln:110,lt:3},
          ];

          var SEV=[
            {r:255,g:50, b:50, lbl:'CRITICAL',w:0.35},
            {r:255,g:140,b:0,  lbl:'HIGH',    w:0.30},
            {r:255,g:220,b:0,  lbl:'MEDIUM',  w:0.20},
            {r:0,  g:180,b:255,lbl:'INFO',    w:0.15},
          ];

          var arcs=[], atkCount=142389+Math.floor(Math.random()*80000);
          var lastSpawn=0, frame=0, scanX=0;
          var atkEl=document.getElementById('cdb-atk-count');
          if(atkEl) atkEl.textContent=atkCount.toLocaleString();

          /* pick weighted severity */
          function pickSev(){
            var r=Math.random(),cum=0;
            for(var i=0;i<SEV.length;i++){cum+=SEV[i].w;if(r<cum)return SEV[i];}
            return SEV[0];
          }

          /* spawn one attack arc */
          function spawnArc(){
            var si=Math.floor(Math.random()*NODES.length);
            var di=Math.floor(Math.random()*NODES.length);
            while(di===si)di=Math.floor(Math.random()*NODES.length);
            var sv=pickSev();
            var spd=0.007+Math.random()*0.012;
            arcs.push({
              sln:NODES[si].ln,slt:NODES[si].lt,
              dln:NODES[di].ln,dlt:NODES[di].lt,
              sn:NODES[si].n, dn:NODES[di].n,
              sv:sv,t:0,spd:spd,alpha:0,life:'in',trail:[]
            });
            atkCount++;
            if(atkEl) atkEl.textContent=atkCount.toLocaleString();
          }

          /* bezier interpolation */
          function bz(t,p0,p1,p2){var m=1-t;return m*m*p0+2*m*t*p1+t*t*p2;}

          /* draw country path */
          function drawCountry(rings,fill,stroke,lw){
            for(var ri=0;ri<rings.length;ri++){
              var pts=rings[ri]; if(pts.length<3) continue;
              ctx.beginPath();
              var p0=px(pts[0][0],pts[0][1]);
              ctx.moveTo(p0[0],p0[1]);
              for(var pi=1;pi<pts.length;pi++){
                var pp=px(pts[pi][0],pts[pi][1]);
                ctx.lineTo(pp[0],pp[1]);
              }
              ctx.closePath();
              if(fill){ctx.fillStyle=fill;ctx.fill();}
              if(stroke){ctx.strokeStyle=stroke;ctx.lineWidth=lw||0.5;ctx.stroke();}
            }
          }

          /* draw graticule (lat/lon grid lines) */
          function drawGraticule(){
            ctx.save();
            ctx.strokeStyle='rgba(0,212,170,0.04)';
            ctx.lineWidth=0.5;
            /* longitude lines every 30° */
            for(var ln=-180;ln<=180;ln+=30){
              var p=px(ln,80); var pe=px(ln,-55);
              ctx.beginPath(); ctx.moveTo(p[0],p[1]); ctx.lineTo(pe[0],pe[1]); ctx.stroke();
            }
            /* latitude lines every 30° */
            for(var lt=-60;lt<=80;lt+=30){
              var pl=px(-180,lt); var pr=px(180,lt);
              ctx.beginPath(); ctx.moveTo(pl[0],pl[1]); ctx.lineTo(pr[0],pr[1]); ctx.stroke();
            }
            /* equator brighter */
            ctx.strokeStyle='rgba(0,212,170,0.09)';
            ctx.lineWidth=0.7;
            var eq0=px(-180,0),eq1=px(180,0);
            ctx.beginPath(); ctx.moveTo(eq0[0],eq0[1]); ctx.lineTo(eq1[0],eq1[1]); ctx.stroke();
            ctx.restore();
          }

          /* draw the map background + countries */
          function drawMap(){
            /* ocean */
            ctx.fillStyle='#040e1a'; ctx.fillRect(0,0,W,H);
            /* subtle scan glow */
            scanX=(scanX+0.2)%W;
            var sg=ctx.createLinearGradient(scanX-60,0,scanX+4,0);
            sg.addColorStop(0,'rgba(0,212,170,0)');
            sg.addColorStop(1,'rgba(0,212,170,0.04)');
            ctx.fillStyle=sg; ctx.fillRect(0,0,scanX,H);
            /* graticule */
            drawGraticule();
            /* country fills + borders */
            for(var ci=0;ci<CTRY.length;ci++){
              var ct=CTRY[ci];
              drawCountry(ct.p,'rgba(0,46,34,0.75)','rgba(0,130,90,0.55)',0.6);
            }
            /* country labels */
            ctx.save();
            ctx.font='bold 6px "Courier New",monospace';
            ctx.textAlign='center';
            ctx.textBaseline='middle';
            for(var ci2=0;ci2<CTRY.length;ci2++){
              var ct2=CTRY[ci2];
              if(!ct2.n) continue;
              var lp=px(ct2.lb[0],ct2.lb[1]);
              /* only draw if within canvas */
              if(lp[0]>2&&lp[0]<W-2&&lp[1]>2&&lp[1]<H-2){
                ctx.fillStyle='rgba(0,220,160,0.55)';
                ctx.fillText(ct2.n,lp[0],lp[1]);
              }
            }
            ctx.restore();
          }

          /* draw attack nodes */
          function drawNodes(){
            ctx.save();
            for(var ni=0;ni<NODES.length;ni++){
              var nd=NODES[ni];
              var np=px(nd.ln,nd.lt);
              var pulse=0.5+0.5*Math.sin(frame*0.06+ni*0.8);
              /* outer ring */
              ctx.beginPath(); ctx.arc(np[0],np[1],2.5+pulse*0.8,0,Math.PI*2);
              ctx.fillStyle='rgba(0,212,170,'+(0.08+0.1*pulse)+')'; ctx.fill();
              /* center dot */
              ctx.beginPath(); ctx.arc(np[0],np[1],1.2,0,Math.PI*2);
              ctx.fillStyle='rgba(0,212,170,'+(0.5+0.4*pulse)+')'; ctx.fill();
            }
            ctx.restore();
          }

          /* draw all attack arcs */
          function drawArcs(){
            var alive=[];
            for(var ai=0;ai<arcs.length;ai++){
              var a=arcs[ai];
              /* lifecycle */
              if(a.life==='in'){a.alpha=Math.min(1,a.alpha+0.07);if(a.alpha>=1)a.life='go';}
              else if(a.life==='out'){a.alpha=Math.max(0,a.alpha-0.06);}
              a.t+=a.spd;
              if(a.t>1.25)a.life='out';
              if(a.life==='out'&&a.alpha<=0) continue;
              var t=Math.min(a.t,1);
              /* screen coords */
              var sp=px(a.sln,a.slt), dp=px(a.dln,a.dlt);
              var r=a.sv.r,g=a.sv.g,b=a.sv.b;
              /* control point — arc above midpoint */
              var mx=(sp[0]+dp[0])/2, my=(sp[1]+dp[1])/2;
              var dx=dp[0]-sp[0], dy=dp[1]-sp[1];
              var dist=Math.sqrt(dx*dx+dy*dy);
              var lift=Math.min(dist*0.4, H*0.35);
              var cpx=mx, cpy=my-lift;
              /* draw trail */
              var t0=Math.max(0,t-0.3), steps=32;
              ctx.save(); ctx.lineWidth=1.4;
              for(var s=0;s<steps;s++){
                var st=t0+(t-t0)*s/steps, st1=t0+(t-t0)*(s+1)/steps;
                if(st1>1)break;
                var x0=bz(st, sp[0],cpx,dp[0]), y0=bz(st, sp[1],cpy,dp[1]);
                var x1=bz(st1,sp[0],cpx,dp[0]), y1=bz(st1,sp[1],cpy,dp[1]);
                var frac=s/steps;
                ctx.beginPath(); ctx.moveTo(x0,y0); ctx.lineTo(x1,y1);
                ctx.strokeStyle='rgba('+r+','+g+','+b+','+(a.alpha*frac*0.95)+')';
                ctx.stroke();
              }
              ctx.restore();
              /* head dot */
              if(t<=1){
                var hx=bz(t,sp[0],cpx,dp[0]), hy=bz(t,sp[1],cpy,dp[1]);
                ctx.beginPath(); ctx.arc(hx,hy,2.8,0,Math.PI*2);
                ctx.fillStyle='rgba('+r+','+g+','+b+','+a.alpha+')'; ctx.fill();
                /* glow halo */
                ctx.beginPath(); ctx.arc(hx,hy,5.5,0,Math.PI*2);
                ctx.fillStyle='rgba('+r+','+g+','+b+','+(a.alpha*0.2)+')'; ctx.fill();
              }
              /* impact ring at destination */
              if(t>=0.92&&t<=1){
                var ex=dp[0], ey=dp[1];
                var esz=(t-0.92)*22*a.alpha;
                ctx.beginPath(); ctx.arc(ex,ey,esz,0,Math.PI*2);
                ctx.strokeStyle='rgba('+r+','+g+','+b+','+(a.alpha*(1-t)*11)+')';
                ctx.lineWidth=1.2; ctx.stroke();
                /* second ring */
                if(esz>4){
                  ctx.beginPath(); ctx.arc(ex,ey,esz*0.5,0,Math.PI*2);
                  ctx.strokeStyle='rgba('+r+','+g+','+b+','+(a.alpha*(1-t)*6)+')';
                  ctx.lineWidth=0.8; ctx.stroke();
                }
              }
              alive.push(a);
            }
            arcs=alive;
          }

          /* overlay: LIVE badge + legend */
          function drawOverlay(){
            /* LIVE badge */
            ctx.save();
            ctx.fillStyle='rgba(255,40,40,0.18)'; ctx.fillRect(W-42,3,38,14);
            ctx.strokeStyle='rgba(255,60,60,0.7)'; ctx.lineWidth=0.7; ctx.strokeRect(W-42,3,38,14);
            ctx.fillStyle='#ff4444'; ctx.font='bold 8px monospace';
            ctx.textAlign='center'; ctx.fillText('LIVE',W-23,13);
            ctx.restore();
            /* severity legend */
            var leg=[
              {c:'rgb(255,50,50)',l:'CRIT'},
              {c:'rgb(255,140,0)',l:'HIGH'},
              {c:'rgb(255,220,0)',l:'MED'},
              {c:'rgb(0,180,255)',l:'INFO'},
            ];
            ctx.save();
            for(var li=0;li<leg.length;li++){
              var lx=4+li*52;
              ctx.fillStyle=leg[li].c; ctx.fillRect(lx,4,7,7);
              ctx.fillStyle='rgba(180,210,230,0.65)';
              ctx.font='7px monospace'; ctx.textAlign='left';
              ctx.fillText(leg[li].l,lx+9,11);
            }
            ctx.restore();
          }

          /* MAIN LOOP */
          function draw(ts){
            requestAnimationFrame(draw);
            frame++;
            if(!lastSpawn||ts-lastSpawn>500+Math.random()*600){
              spawnArc();
              if(Math.random()<0.4) spawnArc();
              lastSpawn=ts;
            }
            ctx.clearRect(0,0,W,H);
            drawMap();
            drawNodes();
            drawArcs();
            drawOverlay();
          }
          requestAnimationFrame(draw);
        }

        if(document.readyState==='loading'){
          document.addEventListener('DOMContentLoaded',cdbInitThreatMap);
        } else { setTimeout(cdbInitThreatMap,200); }
        })();
        /* ═══ END CDB LIVE CYBER THREAT MAP ═══ */
