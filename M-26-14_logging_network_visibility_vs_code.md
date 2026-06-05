# OMB Memorandum M-26-14: Ensuring Effective and Efficient Agency Logging and Network Visibility to Defend Against Evolving Cyber Threats

**Source document:** Executive Office of the President, Office of Management and Budget memorandum M-26-14  
**Date:** May 22, 2026  
**From:** Russell T. Vought, Director, Office of Management and Budget  
**To:** Heads of Executive Departments and Agencies  
**Subject:** Ensuring Effective and Efficient Agency Logging and Network Visibility to Defend Against Evolving Cyber Threats

## Purpose

This memorandum directs Federal agencies to adopt a risk-based and prioritized logging approach that supports effective and efficient network monitoring, cyber defense, incident response, investigation, and forensic analysis.

The memorandum recognizes that threat actors increasingly use automation and artificial intelligence to accelerate cyberattacks against critical systems. These capabilities can help threat actors gain unauthorized access, move laterally across systems, and maintain undetected access for extended periods. To reduce this risk, agencies need the ability to rapidly detect, respond to, and analyze anomalous network activity.

Event logging is central to this requirement. Logs provide timely and consistent records of significant system activity. Agencies use logs to understand activity across their systems, identify events requiring attention, and support analysis and response actions that protect sensitive data and sustain operations.

## Relationship to OMB Memorandum M-21-31

OMB Memorandum M-21-31, *Improving the Federal Government's Investigative and Remediation Capabilities Related to Cybersecurity Incidents*, is rescinded effective immediately.

M-21-31 raised logging baselines and improved agencies' foundational visibility into activity across their systems. However, some requirements, including retention of very large quantities of logging data without clear operational utility, proved neither operationally feasible nor cost-effective for most agencies.

M-26-14 replaces that approach with an adaptive framework intended to help agencies monitor their networks effectively and efficiently while reducing unnecessary administrative burden and containing costs.

## Applicability

For purposes of this memorandum, **agency** has the meaning given in 44 U.S.C. § 3502.

The requirements apply to all information systems owned or operated by an agency, or by third parties on an agency's behalf. This includes Internet of Things (IoT) devices and operational technology (OT) that are part of, or constitute, an agency information system.

For purposes of this memorandum, **information system** has the meaning given in 44 U.S.C. § 3502(8).

The requirements do not apply to national security systems, as defined in 44 U.S.C. § 3552(b)(6), or to systems of the Department of Defense or Intelligence Community described in 44 U.S.C. § 3553(e).

## Priority Objectives

Agencies must organize and resource logging activities around two primary objectives: Continuous Event Monitoring (CEM) and Threat Hunting, Investigation, Response, and Forensics (THIRF).

### Continuous Event Monitoring (CEM)

CEM refers to the logs, log management capabilities, and logging infrastructure that enable agencies to monitor network activity in real time, promptly flag anomalous activity, and respond to that activity in a timely manner.

CEM logs are typically ingested and monitored by a Security Operations Center (SOC).

### Threat Hunting, Investigation, Response, and Forensics (THIRF)

THIRF refers to the logs, log management capabilities, and logging infrastructure that enable agencies to investigate and perform forensic analysis after a known or suspected compromise.

The purpose of THIRF is to mitigate, remediate, and recover from threat actor activity. Agencies must maintain enough hot and cold storage, along with the ability to retrieve and centralize logging data from multiple sources, to map attack patterns and support post-compromise analysis.

## Logging Reference Architecture (LRA)

Within 90 days of the memorandum date, CISA, in coordination with OMB and the CISO Council, will develop a Logging Reference Architecture (LRA).

The LRA must satisfy the requirements in this memorandum and help agencies meet CEM and THIRF objectives. It will serve as a core implementation guide for agency logging capabilities. It is intended to let agencies build on progress made under M-21-31 while allowing flexibility for differing mission requirements and cybersecurity risk profiles.

Agencies must adhere to the LRA according to the timelines listed in the agency actions section of this memorandum.

The LRA will be published at: <https://www.cisa.gov/Logging>

## Agency Logging Plan

Each agency must submit an Agency Logging Plan to OMB and CISA within 90 days of publication of the LRA.

The Agency Logging Plan must describe the operational steps required for the agency to deploy and maintain effective CEM and THIRF capabilities. The plan must document the actions the agency will take to meet the minimum baseline requirements in this memorandum, as well as any additional log collection or logging activities needed to achieve CEM and THIRF objectives.

The plan must account for the agency's threat environment, risk profile, and mission, using the guidance provided in the CISA Logging Reference Architecture.

Agencies should periodically update their Agency Logging Plans as necessary.

## Measuring Maturity

The memorandum establishes a revised logging maturity model to guide and measure implementation.

The model defines performance benchmarks across the following functions:

- Inventory visibility
- Log management planning and operations
- Log collection
- Data retention

Agencies must measure and report progress as the percentage of systems operating at each maturity level.

Overall maturity is calculated using the lowest watermark for each component in the maturity model. In practical terms, if a system reaches a higher level in some elements but remains lower in another, the lower element constrains the overall maturity level.

## Log Access Requirements During Incidents

When there is a known or suspected compromise of one or more Federal networks, agencies must provide logs and other relevant data to CISA and the FBI upon request, to the extent consistent with applicable law.

The purpose of this access is to assist with incident response, investigation, and remediation.

Agencies must provide the requested data in a format and by a method agreed upon by the agency and CISA or the FBI, as appropriate. To the greatest extent practicable, agencies must provide access within the timeframes requested by CISA or the FBI.

If agency data is subject to statutory, regulatory, or judicial access restrictions, the Directors of CISA and the FBI will comply with required access processes and procedures. Where legally available, they may also work with the agency to develop an appropriate administrative accommodation consistent with those restrictions.

## Required Actions and Deadlines

### CISA, OMB, and CISO Council Actions

CISA, in coordination with OMB and the CISO Council, must publish the LRA within 90 days of the memorandum date.

CISA must notify agencies within five business days of any published updates to the LRA.

CISA must provide logging implementation technical support and advice to agencies through appropriate channels. These may include FAQs, interagency engagements such as workshops, focus groups, communities of practice, training, or direct support opportunities.

### Agency Actions After Initial LRA Release

Within 90 days of the release of the LRA, each agency must complete the first version of its Agency Logging Plan. This plan must provide for fulfillment of the memorandum's minimum requirements and must use guidance and resources from the Logging Reference Architecture.

Within 120 days of the release of the LRA, each agency must achieve at least Basic maturity, also called Level 1, across all elements of the maturity model.

Within 180 days of the release of the LRA, each agency must achieve at least Intermediate maturity, also called Level 2, across all elements of the maturity model.

Within 320 days of the release of the LRA, each agency must achieve at least Advanced maturity, also called Level 3, across all elements of the maturity model.

### Ongoing Actions After LRA Updates

After CISA notifies agencies of an updated version of the Logging Reference Architecture, each agency must update its Agency Logging Plan within 30 calendar days.

Within 60 calendar days of CISA notification, each agency must achieve at least Intermediate maturity across all elements of the maturity model.

Within 120 calendar days of CISA notification, each agency must achieve at least Advanced maturity across all elements of the maturity model.

## Policy Assistance

Questions or inquiries about the memorandum should be addressed to the OMB Office of the Federal Chief Information Officer at: <ofcio@omb.eop.gov>

Questions or inquiries about the LRA should be addressed to CISA through resources available at: <https://www.cisa.gov/Logging>

# Appendix A: Base Requirements for the Logging Reference Architecture

The Logging Reference Architecture must address the following topics and requirements.

## Prioritization

The LRA must provide prioritization guidance for achieving CEM and THIRF. The guidance must emphasize High Value Assets and High Impact Systems.

A High Value Asset is identified according to OMB Memorandum M-19-03, *Strengthening the Cybersecurity of Federal Agencies by Enhancing the High Value Asset Program*.

A High Impact System is an information system for which at least one security objective - confidentiality, integrity, or availability - is assigned a potential impact value of "high" under NIST Federal Information Processing Standard (FIPS) 199.

The prioritization guidance must help agencies determine which implementation course best supports CEM and THIRF based on agency mission.

## Alignment With Zero Trust

The LRA must align with CISA's Zero Trust Maturity Model.

CISA's Zero Trust Maturity Model defines Visibility and Analytics as a cross-cutting capability that supports and enables all five Zero Trust pillars. Zero Trust also helps Federal agencies make risk-based implementation decisions in support of CEM and THIRF.

## Log Centralization

The LRA must provide options for building CEM and THIRF capabilities through centralized access deployment, centralized architecture deployment, or a hybrid of both.

Centralization, centralized access, and centralized visibility must occur at each agency's highest-level SOC.

## Log Collection and Sensitive Data Exposure Risk

The LRA must include guidance to ensure that logs do not capture or expose data in violation of law.

The LRA must also advise agencies on how to protect the confidentiality and integrity of sensitive log data.

## IoT and Operational Technology

The LRA must provide guidance for implementing logging capabilities for agency IoT and OT.

This includes IoT devices and OT that do not have native logging capabilities.

## Artificial Intelligence

The LRA must discuss methods for using AI technologies to enhance CEM and THIRF capabilities.

This discussion must reference applicable government-wide AI policy and guidance.

## Self-Assessment

The LRA must explain how agencies may conduct self-assessments of CEM capabilities, THIRF capabilities, and logging maturity.

## Data Retention Guidance

The LRA must offer recommendations on data retention practices that exceed the minimum requirements described in the memorandum.

## Updates

The LRA must be re-evaluated at least once each year for necessary updates, enhancements, and adjustments.

The re-evaluation must account for emerging technologies and changes in the threat landscape, frameworks, strategies, and opportunities.

# Appendix B: Minimum Logging Baseline Requirements and Objectives

## Retention Requirements

Retained logs must be actively searchable for at least 6 months after creation to support CEM.

Retained logs must be retrievable for 1 year after creation to support THIRF.

For this memorandum, **searchable** means the data can be immediately used for cyber defense. Detections and analytics can be applied to the data without additional preparation steps.

For this memorandum, **retrievable** means the data can be used for cyber defense activities after one or more intermediary preparation steps. Data preparation may include actions required to replay data from long-term storage in an analytics tool, move data from an archive into a real-time analysis platform, or thaw data from cold storage into a faster storage tier.

Meeting the memorandum's minimum retention requirements for cybersecurity purposes does not relieve agencies of obligations to comply with other applicable requirements, including agency-specific or government-wide records schedules.

## Storage and SOC Availability

Log storage may be decentralized, but logs must be readily available to the top-level agency SOC to support CEM and THIRF.

Agencies are encouraged to evaluate one or more approaches and to use LRA guidance. Acceptable approaches may include enterprise security information and event management software or equivalent capabilities, forwarding logs to a central location, setting appropriate access authorizations across distributed logs, or using a hybrid approach that combines centralized storage with federated access.

## Timestamp Accuracy

Logs must include a consistently accurate timestamp.

Network time must be synchronized to a traceable time source designated within the agency. The memorandum also states that network time must be synchronized using Network Time Protocol (NTP) or equivalent mechanisms to a traceable time source designated within the agency.

Where feasible, agencies are encouraged to use authoritative time sources traceable to the U.S. Naval Observatory or the National Institute of Standards and Technology (NIST).

## Coverage Validation Through Asset Management Data

Agencies should use tools and resources such as Continuous Diagnostics and Mitigation (CDM), Hardware Asset Management (HWAM), and Software Asset Management (SWAM) data to determine whether log coverage includes all information technology in agency information systems.

This includes IoT devices and OT.
