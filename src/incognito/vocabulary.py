"""Names and words that incognito mode leaves visible to the AI model.

Splunk's own indexes, accounts, and apps, vendor domains, and common words carry meaning the
model needs and identify nothing about a particular deployment, so they are never replaced.
"""

from __future__ import annotations

import re

SPLUNK_DEFAULT_INDEXES = frozenset(
    {
        "_audit",
        "_cmdb",
        "_configtracker",
        "_ds",
        "_dsappevent",
        "_dsclient",
        "_dsphonehome",
        "_internal",
        "_introspection",
        "_metrics",
        "_metrics_rollup",
        "_telemetry",
        "_thefishbucket",
        "cim_modactions",
        "history",
        "lastchanceindex",
        "main",
        "notable",
        "notable_summary",
        "risk",
        "sequenced_events",
        "splunklogger",
        "summary",
        "threat_activity",
        "ba_test",
        "endpoint_summary",
        "whois",
    }
)

PUBLIC_ACCOUNTS = frozenset(
    {
        "admin",
        "administrator",
        "anonymous",
        "guest",
        "local system",
        "localsystem",
        "network service",
        "nobody",
        "root",
        "splunk",
        "splunk-system-user",
        "splunkfwd",
        "system",
        "unknown",
    }
)

# Roles that ship with Splunk Enterprise, Splunk Cloud, and Splunk's premium apps.
SPLUNK_DEFAULT_ROLES = frozenset(
    {
        "admin",
        "apps",
        "can_delete",
        "ess_admin",
        "ess_analyst",
        "ess_user",
        "internal_ops_admin",
        "itoa_admin",
        "itoa_analyst",
        "itoa_team_admin",
        "itoa_user",
        "list_users_roles",
        "power",
        "sc_admin",
        "splunk-system-role",
        "tokens_auth",
        "user",
    }
)

SPLUNK_DEFAULT_APPS = frozenset(
    {
        "alert_logevent",
        "alert_webhook",
        "appsbrowser",
        "dmc",
        "introspection_generator_addon",
        "journald_input",
        "launcher",
        "learned",
        "legacy",
        "python_upgrade_readiness_app",
        "sample_app",
        "search",
        "splunk-dashboard-studio",
        "splunk_archiver",
        "splunk_assist",
        "splunk_essentials",
        "splunk_gdi",
        "splunk_httpinput",
        "splunk_instrumentation",
        "splunk_internal_metrics",
        "splunk_metrics_workspace",
        "splunk_monitoring_console",
        "splunk_rapid_diag",
        "splunk_secure_gateway",
        "splunkclouduf",
        "splunkdeploymentserverconfig",
        "splunkforwarder",
        "splunklightforwarder",
        "system",
        "user-prefs",
    }
)

# Prefixes used by Splunk-built and Splunkbase apps and add-ons.
VENDOR_APP_PREFIXES = (
    "splunk_",
    "splunk-",
    "sa-",
    "sa_",
    "da-",
    "da_",
    "ta-",
    "ta_",
    "dashboard_studio",
    "missioncontrol",
    "itsi",
    "ess_",
    "securitysuite",
)

# Domains that belong to vendors, standards bodies, or documentation, never to a deployment.
PUBLIC_DOMAINS = frozenset(
    {
        "amazon.com",
        "amazonaws.com",
        "anthropic.com",
        "apache.org",
        "ado.net",
        "apple.com",
        "asp.net",
        "azure.com",
        "cisco.com",
        "cloudflare.com",
        "crowdstrike.com",
        "cve.org",
        "docker.com",
        "docker.io",
        "example",
        "example.com",
        "example.net",
        "example.org",
        "github.com",
        "githubusercontent.com",
        "gmail.com",
        "google.com",
        "googleapis.com",
        "invalid",
        "localhost",
        "microsoft.com",
        "microsoftonline.com",
        "mitre.org",
        "mozilla.org",
        "nist.gov",
        "office.com",
        "office365.com",
        "okta.com",
        "openai.com",
        "outlook.com",
        "paloaltonetworks.com",
        "pypi.org",
        "python.org",
        "redhat.com",
        "splunk.com",
        "splunkbase.com",
        "splunkcloud.com",
        "test",
        "socket.io",
        "ubuntu.com",
        "vb.net",
        "w3.org",
        "windows.com",
        "windowsupdate.com",
    }
)

# Multi-tenant services where the subdomain names the customer (acme.splunkcloud.com,
# acme.okta.com). The bare service domain is public; anything under it is masked.
TENANT_DOMAINS = frozenset(
    {
        "amazonaws.com",
        "appspot.com",
        "atlassian.net",
        "azurewebsites.net",
        "cloudapp.net",
        "cloudfront.net",
        "force.com",
        "github.io",
        "googleusercontent.com",
        "herokuapp.com",
        "okta.com",
        "oktapreview.com",
        "onmicrosoft.com",
        "salesforce.com",
        "service-now.com",
        "servicenow.com",
        "sharepoint.com",
        "slack.com",
        "splunkcloud.com",
        "webex.com",
        "windows.net",
        "zendesk.com",
    }
)

# Top-level domains recognized when looking for host and domain names in text. File extensions
# that collide with country codes (for example .py and .md) are excluded through FILE_EXTENSIONS.
DOMAIN_TLDS = frozenset(
    {
        "ad", "ai", "app", "arpa", "au", "biz", "br", "ca", "ch", "cloud", "cn", "co", "com", "corp",
        "de", "dev", "edu", "es", "eu", "fr", "gov", "home", "in", "info", "int", "internal", "intra",
        "intranet", "io", "it", "jp", "kr", "lan", "local", "localdomain", "me", "mil", "net", "nl",
        "nz", "org", "priv", "private", "ru", "se", "site", "tech", "uk", "us", "za",
    }
)

FILE_EXTENSIONS = frozenset(
    {
        "bak", "bat", "cfg", "conf", "cpp", "crt", "csv", "dat", "db", "dll", "doc", "docx", "exe",
        "gif", "gz", "h", "htm", "html", "ini", "jar", "java", "jpeg", "jpg", "js", "json", "key",
        "log", "md", "meta", "msi", "out", "pdf", "pem", "php", "pl", "png", "ps1", "py", "rb", "rpm",
        "sh", "spl", "sql", "svg", "tar", "tgz", "tmp", "ts", "txt", "xls", "xlsx", "xml", "yaml",
        "yml", "zip",
    }
)

# Windows account authorities that look like DOMAIN\\user but name built-in principals.
PUBLIC_NT_AUTHORITIES = frozenset(
    {
        "builtin",
        "font driver host",
        "iis apppool",
        "nt authority",
        "nt service",
        "window manager",
        "authority",
        "service",
    }
)

# Plain words that also appear as index, host, or app names. A real name that is one of these
# words is replaced where it appears as a field value, but not everywhere it occurs in text,
# because replacing a common word throughout a prompt would corrupt the instructions.
GENERIC_WORDS = frozenset(
    """
    access account accounts active ad admin agent agents alert alerts all analytics antivirus api app
    application applications apps archive asset assets audit auth authentication av aws azure backup
    backups base batch billing build business cache central change changes checkpoint cisco cloud
    cluster collector common compliance config configuration console container containers core corp
    critical crowdstrike custom dashboard dashboards data database db debug default demo deployment
    desktop dev development dhcp dns docker domain duo east edge edr email endpoint endpoints error
    errors es esx esxi event events exchange external f5 file files finance firewall firewalls
    forwarder forwarders fortinet ftp gateway gcp general guest health history home host hosts hr http
    https iam identity ids iis inbound index indexer indexers indexes info infra infrastructure
    intel internal inventory ips itsi juniper kafka kerberos kubernetes lab ldap legacy license
    linux load local log logs lookup lookups mail main manager master metric metrics misc mltk mobile
    monitor monitoring mysql netflow network networks new north notable o365 office okta old ops
    oracle os other outbound palo paloalto payments pci peer peers perfmon phantom platform portal
    postgres powershell primary private prod production proxy public qa redis remote report reports
    risk router routers sales sample samples sandbox scratch script scripts search searches secondary
    security server servers service services shared sink smtp soar source sources sourcetype
    sourcetypes south splunk sql ssh staging storage summary switch switches syslog sysmon system
    systems temp test testing threat tmp traffic training uat uba unix user users vmware vpn web west
    windows wineventlog wireless workstation workstations example examples
    """.split()
)

# SPL commands, functions, and common field names. A deployment name that matches one of these
# would corrupt every query and instruction if it were replaced throughout the text.
SPL_TERMS = frozenset(
    """
    abstract accum addcoltotals addinfo addtotals analyzefields anomalies anomalousvalue append
    appendcols appendpipe arules associate audit autoregress bin bucket bucketdir cefout chart cluster
    cofilter collect concurrency contingency convert correlate datamodel dbinspect dedup delete delta
    diff erex eval eventcount eventstats extract fieldformat fields fieldsummary filldown fillnull
    findtypes foreach format from gauge gentimes geom geostats head highlight history iconify inputcsv
    inputlookup iplocation join kmeans kvform loadjob localize localop lookup makecontinuous makemv
    makeresults map mcollect metadata metasearch meventcollect mpreview msearch mstats multikv
    multisearch mvcombine mvexpand nomv outlier outputcsv outputlookup outputtext overlap pivot predict
    rangemap rare regex reltime rename replace require rest return reverse rex rtorder savedsearch
    script scrub search searchtxn selfjoin sendemail set setfields sichart sirare sistats sitimechart
    sitop sort spath stats strcat streamstats table tags tail timechart timewrap tojson top transaction
    transpose trendline tscollect tstats typeahead typelearner typer union uniq untable walklex where
    x11 xmlkv xmlunescape xpath xyseries count dc distinct_count earliest latest values list avg sum min
    max median mode range stdev var perc first last span limit useother usenull partial allnum
    sourcetype source host index splunk_server linecount punct eventtype tag time
    _time _raw _indextime true false null not and or as by with over output outputnew
    """.split()
)

CIM_DATAMODELS = frozenset(
    """
    alerts application_state authentication certificates change change_analysis compute_inventory
    data_access databases data_loss_prevention dlp email endpoint event_signatures interprocess_messaging
    intrusion_detection inventory jvm malware network_resolution network_sessions network_traffic
    performance splunk_audit splunk_cim_validation ticket_management updates vulnerabilities web
    """.split()
)

# Frequent English words. Hosts and apps named after them stay visible in free text and are
# masked only where they appear as field values.
COMMON_WORDS = frozenset(
    """
    about above after again against also always among another answer any anything are area around ask
    away back because been before begin being below best better between both bring call came can case
    change check clear close come could daily day days does done down during each early either else
    end enough even every fact far feel few find first follow found free from full get give good great
    group hand have help here high hold hour hours how idea important into issue just keep kind know
    large last late later lead least leave left less let level life light like line little long look
    made make many may mean might month more most move much must name near need never next night none
    note now number off often once only open order other our out over own part past people place plan
    point possible power present problem public question quick quite rather read real reason result
    results right run same say second see seem self send set several shall should show side since small
    some something soon start state still stop such sure take tell than that the their them then there
    these they thing think this those though three through today together too total toward true turn
    under until upon use used using value very want was watch way week well were what when where which
    while who whole why will within without word work world would year years yes yet you your zone
    """.split()
)

_VERSION_LIKE = re.compile(r"^v?\d+(?:[._-]\d+)*$")
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_DASHED_IPV4 = re.compile(rf"^{_OCTET}(?:-{_OCTET}){{3}}$")


def is_dashed_ipv4(value: str) -> bool:
    """Whether a name spells out an IPv4 address with dashes (10-1-2-3), as cloud and DHCP host names do."""
    return bool(_DASHED_IPV4.match(value.strip()))


def is_vendor_app(name: str) -> bool:
    lowered = name.strip().lower()
    return lowered in SPLUNK_DEFAULT_APPS or lowered.startswith(VENDOR_APP_PREFIXES)


# Shipped apps where people save their own searches, macros, and dashboards.
GENERAL_PURPOSE_APPS = frozenset({"launcher", "learned", "legacy", "sample_app", "search", "system", "user-prefs"})


def is_shipped_content_app(name: str) -> bool:
    """Whether knowledge objects in an app are vendor content whose names can stay visible."""
    return is_vendor_app(name) and name.strip().lower() not in GENERAL_PURPOSE_APPS


def is_public_domain(domain: str) -> bool:
    lowered = domain.strip().lower().rstrip(".")
    if lowered in PUBLIC_DOMAINS or lowered in TENANT_DOMAINS:
        return True
    if any(lowered.endswith("." + tenant) for tenant in TENANT_DOMAINS):
        return False
    return any(lowered.endswith("." + public) for public in PUBLIC_DOMAINS)


def is_public_value(namespace: str, value: str) -> bool:
    """Whether a value in a namespace is shared vocabulary rather than a deployment's own name."""
    lowered = value.strip().lower()
    if not lowered or lowered in {"*", "-", "n/a", "none", "null", "unknown"}:
        return True
    if namespace == "index":
        return lowered in SPLUNK_DEFAULT_INDEXES
    if namespace == "user":
        return lowered in PUBLIC_ACCOUNTS
    if namespace == "role":
        return lowered in SPLUNK_DEFAULT_ROLES
    if namespace == "app":
        return is_vendor_app(lowered)
    if namespace == "domain":
        return is_public_domain(lowered)
    if namespace == "host":
        return lowered in {"localhost", "localhost.localdomain"}
    return False


def is_free_text_term(value: str) -> bool:
    """Whether a real name is distinctive enough to replace everywhere it appears in text.

    Very short names, numbers, version strings, and plain words are only replaced where they
    appear as field values, so ordinary words and counts in a prompt are left alone.
    """
    stripped = value.strip()
    if is_dashed_ipv4(stripped):
        return True
    if len(stripped) < 3 or _VERSION_LIKE.match(stripped):
        return False
    lowered = stripped.lower()
    for vocabulary in (GENERIC_WORDS, SPL_TERMS, CIM_DATAMODELS, COMMON_WORDS, SPLUNK_DEFAULT_INDEXES,
                       PUBLIC_ACCOUNTS, SPLUNK_DEFAULT_APPS, SPLUNK_DEFAULT_ROLES):
        if lowered in vocabulary:
            return False
    if lowered.isalpha() and len(lowered) <= 3:
        return False
    return True
