#!/usr/bin/env python3
"""
visualizer.py — CyberDudeBivash v1.0
Spatial Intelligence: Heat Map Generation for Global Threats.
"""
import logging
from typing import List, Dict

logger = logging.getLogger("CDB-VISUALIZER")

class ThreatVisualizer:
    def __init__(self):
        # Base template for a simplified SVG-based World Map
        self.svg_template = """
        <div style="background: #f1f3f4; padding: 20px; border-radius: 8px; text-align: center;">
            <h3 style="color: #1a1f36; margin-bottom: 15px;">GLOBAL THREAT DISTRIBUTION</h3>
            <svg viewBox="0 0 1000 500" xmlns="http://www.w3.org/2000/svg" style="max-width: 100%; height: auto; background: #ffffff; border: 1px solid #e3e8ee;">
                <rect width="1000" height="500" fill="#f8f9fa"/>
                {map_points}
            </svg>
            <p style="font-size: 11px; color: #a3acb9; margin-top: 10px;">* Red pulses indicate active IoC origins triaged in this sweep.</p>
        </div>
        """

    def generate_heat_map(self, pro_data: Dict) -> str:
        """Translates Geo-IP coordinates into SVG pulse points."""
        points = []
        # Logical mapping of common regions to SVG coordinates (Simplified for Static HTML)
        region_map = {
            "United States": (200, 180), "China": (780, 200), "Russia": (750, 100),
            "Germany": (510, 140), "India": (700, 250), "Brazil": (350, 380),
            "Netherlands": (500, 130), "United Kingdom": (485, 130)
        }

        found_regions = set()
        if pro_data:
            for val in pro_data.values():
                location = val.get("location", "")
                for country, coords in region_map.items():
                    if country in location:
                        found_regions.add(coords)

        for x, y in found_regions:
            points.append(f'<circle cx="{x}" cy="{y}" r="8" fill="#cf1124" opacity="0.6">')
            points.append(f'<animate attributeName="r" from="5" to="15" dur="1.5s" begin="0s" repeatCount="indefinite" />')
            points.append(f'<animate attributeName="opacity" from="0.6" to="0" dur="1.5s" begin="0s" repeatCount="indefinite" />')
            points.append('</circle>')
            points.append(f'<circle cx="{x}" cy="{y}" r="4" fill="#cf1124" />')

        return self.svg_template.format(map_points="".join(points))

# Global Instance
visualizer = ThreatVisualizer()
