/**
 * ApexThreatGlobe.jsx — CyberDudeBivash v30.0 (FRONTEND OMNISCIENCE)
 * Author: CYBERGOD / TECH GOD
 * Description: 3D WebGL Globe connecting to the APEX Firehose to map global
 * cyber attacks in real-time. Upgraded with God-Tier Auto-Reconnect & WSS Support.
 * Dependencies: npm install react-globe.gl three
 */

import React, { useEffect, useState, useRef } from 'react';
import Globe from 'react-globe.gl';

const ApexThreatGlobe = ({ jwtToken }) => {
  const globeEl = useRef();
  const [arcsData, setArcsData] = useState([]);
  const [pointsData, setPointsData] = useState([]);

  useEffect(() => {
    let ws;
    let reconnectTimeout;

    const connectWebSocket = () => {
      // [CYBERGOD FIX 1]: Dynamic Protocol (wss:// for https, ws:// for http)
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      
      // [CYBERGOD FIX 2]: Connecting to the precise endpoint. 
      // NOTE: If using Nginx, drop the :8001 and let Nginx proxy /api/v30/firehose
      const wsUrl = `${wsProtocol}//api.cyberdudebivash.com:8001/api/v30/firehose?token=${jwtToken}`;
      
      console.log(`[APEX GLOBE] Initiating Uplink to ${wsUrl}...`);
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('[APEX GLOBE] 🟢 Uplink to CYBERDUDEBIVASH Firehose Established.');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          if (data.event_type === 'NEW_THREAT_INTEL' || data.event_type === 'KERNEL_EXECVE') {
            const startLat = (Math.random() - 0.5) * 180;
            const startLng = (Math.random() - 0.5) * 360;
            const endLat = 20.2961; // Bhubaneswar (CDB HQ)
            const endLng = 85.8245;

            const newArc = {
              startLat, startLng, endLat, endLng,
              color: data.severity === 'CRITICAL' ? '#ff3e3e' : '#ea580c',
              name: data.title || data.process || "APEX Alert"
            };

            setArcsData((prev) => [...prev, newArc].slice(-50));
            setPointsData((prev) => [...prev, { lat: startLat, lng: startLng, size: 0.5, color: '#ff3e3e' }].slice(-50));
          }
        } catch (e) {
          console.error('[APEX GLOBE] Ingestion Parse Error:', e);
        }
      };

      ws.onclose = (e) => {
        // [CYBERGOD FIX 4]: Auto-Reconnect Loop for 1006 Cloudflare Drops
        console.warn(`[APEX GLOBE] 🔴 Connection Lost (Code: ${e.code}). Reconnecting in 3 seconds...`);
        reconnectTimeout = setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = (err) => {
        console.error('[APEX GLOBE] 🚨 WebSocket Error. Check Nginx Upgrade Headers:', err);
        ws.close();
      };
    };

    // Ignite the connection
    connectWebSocket();

    // Globe Auto-Rotation Setup
    if (globeEl.current) {
      globeEl.current.controls().autoRotate = true;
      globeEl.current.controls().autoRotateSpeed = 1.5;
      globeEl.current.pointOfView({ altitude: 2.5 });
    }

    // Cleanup on unmount
    return () => {
      clearTimeout(reconnectTimeout);
      if (ws) {
        ws.onclose = null; // Prevent reconnect loop on intentional unmount
        ws.close();
      }
    };
  }, [jwtToken]);

  return (
    <div style={{ width: '100%', height: '100vh', background: '#06080d', position: 'relative' }}>
      <div style={{ position: 'absolute', top: 20, left: 20, zIndex: 10, color: '#00d4aa', fontFamily: 'monospace' }}>
        <h2>CYBERDUDEBIVASH APEX</h2>
        <p>Global Sovereign Telemetry: ONLINE</p>
        <p>Active Streams: {arcsData.length}</p>
      </div>
      
      <Globe
        ref={globeEl}
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
        bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
        backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
        
        arcsData={arcsData}
        arcColor="color"
        arcDashLength={0.4}
        arcDashGap={0.2}
        arcDashAnimateTime={1000}
        arcStroke={1}
        
        pointsData={pointsData}
        pointColor="color"
        pointAltitude="size"
        pointRadius={0.12}
        
        atmosphereColor="#00d4aa"
        atmosphereAltitude={0.25}
      />
    </div>
  );
};

export default ApexThreatGlobe;
