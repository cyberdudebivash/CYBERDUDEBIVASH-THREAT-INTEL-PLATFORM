/**
 * ApexThreatGlobe.jsx — CyberDudeBivash v30.0 (FRONTEND OMNISCIENCE)
 * Author: CYBERGOD / TECH GOD
 * Deployment: Root Directory (Parallel to CDB-SENTINEL-Dashboard.jsx)
 */

import React, { useEffect, useState, useRef } from 'react';
import Globe from 'react-globe.gl';

const ApexThreatGlobe = ({ jwtToken }) => {
  const globeEl = useRef();
  const [arcsData, setArcsData] = useState([]);
  const [pointsData, setPointsData] = useState([]);

  useEffect(() => {
    // Zero Regression: Connects to the isolated v30 Firehose
    const ws = new WebSocket(`ws://api.cyberdudebivash.com/api/v30/firehose?token=${jwtToken}`);

    ws.onopen = () => {
      console.log('[APEX GLOBE] Uplink to CyberDudeBivash Firehose Established.');
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      if (data.event_type === 'NEW_THREAT_INTEL' || data.event_type === 'KERNEL_EXECVE') {
        const startLat = (Math.random() - 0.5) * 180;
        const startLng = (Math.random() - 0.5) * 360;
        const endLat = 20.2961; // Bhubaneswar (CDB HQ)
        const endLng = 85.8245;

        const newArc = {
          startLat, startLng, endLat, endLng,
          color: data.severity === 'CRITICAL' ? '#ff3e3e' : '#ea580c',
          name: data.title || data.process
        };

        setArcsData((prev) => [...prev, newArc].slice(-50));
        setPointsData((prev) => [...prev, { lat: startLat, lng: startLng, size: 0.5, color: '#ff3e3e' }].slice(-50));
      }
    };

    if (globeEl.current) {
      globeEl.current.controls().autoRotate = true;
      globeEl.current.controls().autoRotateSpeed = 1.5;
      globeEl.current.pointOfView({ altitude: 2.5 });
    }

    return () => ws.close();
  }, [jwtToken]);

  return (
    <div style={{ width: '100%', height: '500px', background: '#06080d', borderRadius: '12px', overflow: 'hidden', position: 'relative' }}>
      <div style={{ position: 'absolute', top: 20, left: 20, zIndex: 10, color: '#00d4aa', fontFamily: 'monospace' }}>
        <h3>APEX LIVE TELEMETRY</h3>
        <p>Active Enterprise Streams: {arcsData.length}</p>
      </div>
      <Globe
        ref={globeEl}
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
        bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
        arcsData={arcsData}
        arcColor="color"
        arcDashLength={0.4}
        arcDashGap={0.2}
        arcDashAnimateTime={1000}
        pointsData={pointsData}
        pointColor="color"
        pointAltitude="size"
        atmosphereColor="#00d4aa"
      />
    </div>
  );
};

export default ApexThreatGlobe;