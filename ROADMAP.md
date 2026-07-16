# Doors AI — Development Roadmap

## Phase 1 — Stable MVP (Current Focus)

- Local dashboard
- File monitoring
- Malware hash database
- AI file classification
- Process monitoring
- Threat logs
- Quarantine system
- Manual response controls

## Phase 2 — Intelligent Endpoint Protection

- Advanced behavioral detection
- Real-time protection engine
- Persistence detection
- Ransomware detection
- Registry monitoring
- Scheduled task monitoring
- Service monitoring
- Script and macro detection

## Phase 3 — Network Security

- Device discovery
- Port scanning
- Traffic monitoring
- DNS analysis
- VPN/proxy detection
- Threat intelligence integration
- Vulnerability assessment

## Phase 4 — Autonomous AI

- Natural-language AI assistant
- Multi-agent collaboration
- Automatic incident investigation
- Root-cause analysis
- Autonomous containment
- Predictive threat detection

## Phase 5 — Enterprise Platform

- Centralized cloud management
- Multi-tenant organizations
- Remote endpoint management
- Policy enforcement
- SIEM/SOAR integrations
- Compliance reporting
- Scalable deployment

## Beyond the Original Vision

- Kernel-level telemetry (using Windows ETW and kernel callbacks where appropriate) for deeper visibility.
- Attack chain correlation using frameworks like MITRE ATT&CK to connect related events into a single incident.
- Deception technology, such as honeypot files and fake credentials, to detect attackers early.
- Memory analysis for detecting fileless malware and in-memory payloads.
- Identity protection, monitoring for credential theft, token abuse, and abnormal authentication behavior.
- Container and virtualization monitoring for Docker and virtual machines.
- Cloud workload protection for AWS, Azure, and Google Cloud resources.
- Plugin architecture so researchers and developers can add custom detection modules without changing the core platform.
- Threat replay and simulation, allowing users to safely replay captured attacks to validate new detection rules.
- Security posture scoring, giving users an easy-to-understand security health score with prioritized recommendations.
- Digital forensics toolkit, including artifact collection, timeline generation, and evidence preservation after an incident.
