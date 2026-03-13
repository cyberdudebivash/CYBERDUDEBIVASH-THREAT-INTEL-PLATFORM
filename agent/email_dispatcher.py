"""
email_dispatcher.py — CyberDudeBivash Executive Briefing v1.1
Automated B2B email dispatch for high-priority threat intelligence.
"""

import os
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

logger = logging.getLogger("CDB-EMAIL")

def send_executive_briefing(title: str, score: float, content_html: str, url: str):
    """Sends a formatted HTML briefing to the enterprise subscriber list."""
    
    api_key = os.getenv("SENDGRID_API_KEY")
    sender = os.getenv("SENDER_EMAIL")
    # Expecting a comma-separated string in GitHub Secrets
    recipients = os.getenv("SUBSCRIBER_EMAILS", "").split(",") 

    if not api_key or not sender or not recipients or not recipients[0]:
        logger.warning("Email configuration incomplete. Skipping dispatch.")
        return

    # Severity Color Mapping
    color = "#ff3e3e" if score >= 8.5 else "#ff9f43" if score >= 6.5 else "#00e5c3"
    
    # Clean up content for preview (remove script tags/heavy HTML)
    preview_text = "Analysis of critical threat indicators and automated forensic triage."

    html_payload = f"""
    <div style="background:#06080d; color:#94a3b8; font-family:'Segoe UI',Arial,sans-serif; padding:30px; border:1px solid #1e293b; max-width:600px; margin:auto;">
        <div style="border-left:5px solid {color}; padding-left:20px; margin-bottom:25px;">
            <h1 style="color:#ffffff; font-size:22px; margin:0; letter-spacing:1px;">EXECUTIVE THREAT BRIEFING</h1>
            <p style="color:{color}; font-weight:bold; letter-spacing:2px; margin:5px 0; font-size:12px;">CDB-RISK INDEX: {score}/10.0</p>
        </div>
        
        <h2 style="color:#ffffff; font-size:18px; line-height:1.4;">{title}</h2>
        <p style="line-height:1.6; font-size:15px;">{preview_text}</p>
        
        <div style="margin:35px 0; text-align:center;">
            <a href="{url}" style="background:{color}; color:#000000; padding:14px 28px; text-decoration:none; font-weight:900; border-radius:4px; display:inline-block;">ACCESS FULL INTELLIGENCE & JSON</a>
        </div>
        
        <div style="background:#0a0e17; padding:15px; border-radius:8px; border:1px solid #1e293b; font-size:13px;">
            <strong>Pro Tip:</strong> Use the "Download JSON" button in the report to ingest these IoCs directly into your SIEM/Firewall.
        </div>

        <hr style="border:0; border-top:1px solid #1e293b; margin:30px 0;">
        <p style="font-size:11px; text-align:center; line-height:1.5;">
            © 2026 <strong>CYBERDUDEBIVASH PVT LTD</strong><br>
            Global Digital Sovereignty — SOC Triage & AI Threat Intel<br>
            <a href="https://wa.me/918179881447" style="color:{color}; text-decoration:none; font-weight:700;">REQUEST CONSULTATION</a>
        </p>
    </div>
    """

    sg = SendGridAPIClient(api_key)
    for recipient in recipients:
        recipient = recipient.strip()
        message = Mail(
            from_email=sender,
            to_emails=recipient,
            subject=f"CDB ALERT [{score}]: {title}",
            html_content=html_payload
        )
        try:
            sg.send(message)
            logger.info(f"✓ Executive Briefing dispatched to: {recipient}")
        except Exception as e:
            logger.error(f"Email dispatch failed for {recipient}: {e}")
