@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
del /f ".git\index.lock" 2>nul
"C:\Program Files\Git\cmd\git.exe" add .
"C:\Program Files\Git\cmd\git.exe" commit -m "feat: Phase 85-95 Customer Operations Infrastructure - 19 production files

Backend Engines:
- customer_identity_engine.py (Phase 85) - Org/tenant/user/RBAC/MFA/SSO/audit
- tenant_management_engine.py (Phase 85) - Multi-tenant isolation & quota mgmt
- subscription_engine.py (Phase 87) - Plans/upgrades/downgrades/trials/renewals
- billing_engine.py (Phase 87) - Invoicing/usage metering/payment tracking
- customer_health_engine.py (Phase 89) - Health scoring/churn detection/CS engine
- support_operations_engine.py (Phase 90) - Ticketing/SLA/escalation/metrics
- mssp_operations_engine.py (Phase 91) - Multi-tenant MSSP partner ops
- executive_reporting_engine.py (Phase 92) - Weekly/Monthly/Quarterly/Board reports
- renewal_engine.py (Phase 94) - Renewal scoring/expansion/revenue forecast
- customer_ops_center.py (Phase 95) - Master ops aggregator/scale simulation

UI Dashboards:
- customer-portal.html - Unified customer workspace
- customer-dashboard.html - Daily ops dashboard w/ ATT&CK heatmap
- billing-center.html - Subscription & invoice management
- support-center.html - Enterprise ticketing w/ live SLA timers
- customer-success-center.html - Health score grid & churn alerts
- mssp-customer-center.html - Multi-tenant MSSP console
- executive-reporting-center.html - Board & exec reporting center
- api-management-center.html - Developer portal & webhook mgmt
- customer-ops-center.html - Global ops command center

Sentinel APEX is now a fully operational customer-serving cybersecurity infrastructure."
"C:\Program Files\Git\cmd\git.exe" pull --rebase origin main
"C:\Program Files\Git\cmd\git.exe" push origin main
