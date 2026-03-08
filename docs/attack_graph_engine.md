    # Pentra – Attack Graph Engine

## Purpose

The Attack Graph Engine is responsible for modeling how discovered vulnerabilities can be chained together to simulate real-world attacker behavior.

Traditional vulnerability scanners output independent findings.
The Attack Graph Engine transforms those findings into **attack paths**.

Example attack chain:

Subdomain Discovery
→ Exposed API Endpoint
→ IDOR Vulnerability
→ Administrative Access
→ Database Extraction

This capability enables Pentra to simulate realistic offensive security scenarios.

---

## Core Concept

The attack graph is a **directed graph** representing relationships between assets, vulnerabilities, and potential attacker actions.

Graph Components:

Nodes
Represent system entities.

Examples:

* host
* web application
* API endpoint
* cloud resource
* vulnerability
* credential
* privilege level

Edges
Represent attack transitions.

Examples:

* exploit
* lateral movement
* credential usage
* privilege escalation
* API access

---

## Data Sources

The Attack Graph Engine receives structured data from multiple modules:

Reconnaissance
Subdomains, hosts, services

Enumeration
Endpoints, APIs, directories

Vulnerability Scanning
Detected vulnerabilities (CVE, OWASP issues)

Exploit Verification
Confirmed exploit paths

Cloud Analysis
IAM roles, exposed resources

AI Analysis
Contextual vulnerability relationships

---

## Graph Construction Pipeline

1. Asset Graph Creation

Build an initial asset graph representing the discovered attack surface.

Example:

domain
→ subdomain
→ host
→ service
→ endpoint

2. Vulnerability Mapping

Attach vulnerabilities to affected nodes.

Example:

endpoint
→ SQL Injection

3. Exploit Path Modeling

Add edges representing attacker actions.

Example:

SQL Injection
→ Database Access

4. Privilege Modeling

Track privilege levels gained during exploitation.

Example:

user access
→ admin access

5. Attack Path Enumeration

Identify possible attack chains that lead to sensitive targets.

Example:

external access
→ admin privilege
→ data exfiltration

---

## Graph Representation

The attack graph can be represented as:

Directed Acyclic Graph (DAG)

Nodes store:

* asset identifier
* asset type
* vulnerability information
* privilege level

Edges store:

* attack action
* exploit method
* required conditions

---

## Attack Path Scoring

Each attack path receives a risk score based on:

CVSS severity
Exploit availability
Privilege escalation potential
Asset criticality

The system prioritizes paths with highest potential impact.

---

## Example Attack Path

Example scenario detected by Pentra:

1. Subdomain discovered

api.example.com

2. Endpoint enumeration

/api/v1/users

3. Vulnerability detected

IDOR

4. Exploit verification

Access to admin account data

5. Attack path generated

external attacker
→ api endpoint
→ IDOR exploit
→ admin account access
→ sensitive data exposure

---

## Visualization

Attack graphs will be visualized in the Pentra dashboard using an interactive graph view.

Features:

node visualization
attack path highlighting
risk scoring
graph filtering

This allows security teams to quickly understand possible compromise routes.

---

## AI Integration

The AI Analysis module enhances attack graph generation by:

* identifying relationships between vulnerabilities
* predicting exploit chains
* reducing false-positive attack paths
* explaining attack paths in natural language

AI-generated explanations are included in Pentra reports.

---

## Output

The Attack Graph Engine produces:

attack graph data structure
prioritized attack paths
risk scoring
graph visualization data

These outputs feed into:

dashboard visualization
pentest reports
AI analysis modules

---

## Security Constraints

The attack graph engine must only simulate attack paths based on verified findings.

Unverified vulnerabilities must not be used to construct exploit chains unless explicitly marked as hypothetical.

Exploit verification results must be recorded before confirming attack paths.

---

## Future Enhancements

Future versions of the attack graph engine may support:

automatic lateral movement simulation
cloud privilege escalation modeling
zero-day attack prediction
defense strategy recommendations
