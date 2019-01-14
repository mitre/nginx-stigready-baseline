control "V-40791" do
  title "The web server must limit the number of allowed simultaneous session
requests."
  desc  "Web server management includes the ability to control the number of
users and user sessions that utilize a web server. Limiting the number of
allowed users and sessions per user is helpful in limiting risks related to
several types of Denial of Service attacks.

    Although there is some latitude concerning the settings themselves, the
settings should follow DoD-recommended values, but the settings should be
configurable to allow for future DoD direction. While the DoD will specify
recommended values, the values can be adjusted to accommodate the operational
requirement of a given system.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000001-WSR-000001"
  tag "gid": "V-40791"
  tag "rid": "SV-53018r3_rule"
  tag "stig_id": "SRG-APP-000001-WSR-000001"
  tag "fix_id": "F-45918r3_fix"
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if the number of simultaneous sessions is limited.

If the parameter is not configured or is unlimited, this is a finding."
  tag "fix": "Configure the web server to limit the number of concurrent
sessions."

  zones = nginx_conf.http.entries[0].params['limit_conn_zone'].flatten
  describe zones do
    it { should include "$binary_remote_addr" }
  end

  describe describe zones.find { |i| i.match? /default/ } do
    it { should_not be nil }
  end

  describe nginx_conf.http.entries[0].params['limit_conn'].flatten do
    it { should include 'default' }
  end

end

control "V-40792" do
  title "The web server must perform server-side session management."
  desc  "Session management is the practice of protecting the bulk of the user
authorization and identity information. Storing of this data can occur on the
client system or on the server.

    When the session information is stored on the client, the session ID, along
with the user authorization and identity information, is sent along with each
client request and is stored in either a cookie, embedded in the uniform
resource locator (URL), or placed in a hidden field on the displayed form. Each
of these offers advantages and disadvantages. The biggest disadvantage to all
three is the hijacking of a session along with all of the user's credentials.

    When the user authorization and identity information is stored on the
server in a protected and encrypted database, the communication between the
client and web server will only send the session identifier, and the server can
then retrieve user credentials for the session when needed. If, during
transmission, the session were to be hijacked, the user's credentials would not
be compromised.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000001-WSR-000002"
  tag "gid": "V-40792"
  tag "rid": "SV-53023r3_rule"
  tag "stig_id": "SRG-APP-000001-WSR-000002"
  tag "fix_id": "F-45949r2_fix"
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if server-side session management is configured.

If it is not configured, this is a finding."
  tag "fix": "Configure the web server to perform server-side session
management."
end

control "V-40799" do
  title "The web server must generate information to be used by external
applications or entities to monitor and control remote access."
  desc  "Remote access to the web server is any access that communicates
through an external, non-organization-controlled network. Remote access can be
used to access hosted applications or to perform management functions.

    By providing remote access information to an external monitoring system,
the organization can monitor for cyber attacks and monitor compliance with
remote access policies. The organization can also look at data organization
wide and determine an attack or anomaly is occurring on the organization which
might not be noticed if the data were kept local to the web server.

    Examples of external applications used to monitor or control access would
be audit log monitoring systems, dynamic firewalls, or infrastructure
monitoring systems.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000016-WSR-000005"
  tag "gid": "V-40799"
  tag "rid": "SV-53035r3_rule"
  tag "stig_id": "SRG-APP-000016-WSR-000005"
  tag "fix_id": "F-45961r2_fix"
  tag "cci": ["CCI-000067"]
  tag "nist": ["AC-17 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if the web server is configured to generate information for external
applications monitoring remote access.

If a mechanism is not in place providing information to an external application
used to monitor and control access, this is a finding."
  tag "fix": "Configure the web server to provide remote connection information
to external monitoring and access control applications."
end

control "V-40800" do
  title "The web server must use encryption strength in accordance with the
categorization of data hosted by the web server when remote connections are
provided."
  desc  "The web server has several remote communications channels. Examples
are user requests via http/https, communication to a backend database, or
communication to authenticate users. The encryption used to communicate must
match the data that is being retrieved or presented.

    Methods of communication are http for publicly displayed information, https
to encrypt when user data is being transmitted, VPN tunneling, or other
encryption methods to a database.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000014-WSR-000006"
  tag "gid": "V-40800"
  tag "rid": "SV-53037r3_rule"
  tag "stig_id": "SRG-APP-000014-WSR-000006"
  tag "fix_id": "F-45963r2_fix"
  tag "cci": ["CCI-000068"]
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine the communication methods that are being used.

Verify the encryption being used is in accordance with the categorization of
data being hosted when remote connections are provided.

If it is not, then this is a finding."
  tag "fix": "Configure the web server to use encryption strength equal to the
categorization of data hosted when remote connections are provided."
end

control "V-40819" do
  title "The web server must use cryptography to protect the integrity of
remote sessions."
  desc  "Data exchanged between the user and the web server can range from
static display data to credentials used to log into the hosted application.
Even when data appears to be static, the non-displayed logic in a web page may
expose business logic or trusted system relationships. The integrity of all the
data being exchanged between the user and web server must always be trusted. To
protect the integrity and trust, encryption methods should be used to protect
the complete communication session."
  impact 0.5
  tag "gtitle": "SRG-APP-000015-WSR-000014"
  tag "gid": "V-40819"
  tag "rid": "SV-53068r3_rule"
  tag "stig_id": "SRG-APP-000015-WSR-000014"
  tag "fix_id": "F-45994r2_fix"
  tag "cci": ["CCI-001453"]
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to make
certain that the web server is configured to use cryptography to protect the
integrity of remote access sessions.

If the web server is not configured to use cryptography to protect the
integrity of remote access sessions, this is a finding."
  tag "fix": "Configure the web server to utilize encryption during remote
access sessions."
end

control "V-41600" do
  title "The web server must generate, at a minimum, log records for system
startup and shutdown, system access, and system authentication events."
  desc  "Log records can be generated from various components within the web
server (e.g., httpd, plug-ins to external backends, etc.). From a web server
perspective, certain specific web server functionalities may be logged as well.
The web server must allow the definition of what events are to be logged. As
conditions change, the number and types of events to be logged may change, and
the web server must be able to facilitate these changes.

    The minimum list of logged events should be those pertaining to system
startup and shutdown, system access, and system authentication events. If these
events are not logged at a minimum, any type of forensic investigation would be
missing pertinent information needed to replay what occurred.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000089-WSR-000047"
  tag "gid": "V-41600"
  tag "rid": "SV-54177r3_rule"
  tag "stig_id": "SRG-APP-000089-WSR-000047"
  tag "fix_id": "F-47059r3_fix"
  tag "cci": ["CCI-000169"]
  tag "nist": ["AU-12 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and the deployed system
configuration to determine if, at a minimum, system startup and shutdown,
system access, and system authentication events are logged.

If the logs do not include the minimum logable events, this is a finding."
  tag "fix": "Configure the web server to generate log records for system
startup and shutdown, system access, and system authentication events."
end

control "V-41609" do
  title "The web server must capture, record, and log all content related to a
user session."
  desc  "A user session to a web server is in the context of a user accessing a
hosted application that extends to any plug-ins/modules and services that may
execute on behalf of the user.

    The web server must be capable of enabling a setting for troubleshooting,
debugging, or forensic gathering purposes which will log all user session
information related to the hosted application session. Without the capability
to capture, record, and log all content related to a user session,
investigations into suspicious user activity would be hampered.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000093-WSR-000053"
  tag "gid": "V-41609"
  tag "rid": "SV-54186r3_rule"
  tag "stig_id": "SRG-APP-000093-WSR-000053"
  tag "fix_id": "F-47068r2_fix"
  tag "cci": ["CCI-001462"]
  tag "nist": ["AU-14 (2)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if the web server captures and logs all content related to a user
session.

Request a user access the hosted applications and verify the complete session
is logged.

If any of the session is excluded from the log, this is a finding."
  tag "fix": "Configure the web server to capture and log all content related
to a user session."
end

control "V-41611" do
  title "The web server must initiate session logging upon start up."
  desc  "An attacker can compromise a web server during the startup process. If
logging is not initiated until all the web server processes are started, key
information may be missed and not available during a forensic investigation. To
assure all logable events are captured, the web server must begin logging once
the first web server process is initiated."
  impact 0.5
  tag "gtitle": "SRG-APP-000092-WSR-000055"
  tag "gid": "V-41611"
  tag "rid": "SV-54188r3_rule"
  tag "stig_id": "SRG-APP-000092-WSR-000055"
  tag "fix_id": "F-47070r2_fix"
  tag "cci": ["CCI-001464"]
  tag "nist": ["AU-14 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if the web server captures log data as soon as the web server is
started.

If the web server does not capture logable events upon startup, this is a
finding."
  tag "fix": "Configure the web server to capture logable events upon startup."
end

control "V-41612" do
  title "The web server must produce log records containing sufficient
information to establish what type of events occurred."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct type of event that occurred is important during
forensic analysis. The correct determination of the event and when it occurred
is important in relation to other events that happened at that same time.

    Without sufficient information establishing what type of log event
occurred, investigation into the cause of event is severely hindered. Log
record content that may be necessary to satisfy the requirement of this control
includes, but is not limited to, time stamps, source and destination IP
addresses, user/process identifiers, event descriptions, application-specific
events, success/fail indications, file names involved, access control, or flow
control rules invoked.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000095-WSR-000056"
  tag "gid": "V-41612"
  tag "rid": "SV-54189r3_rule"
  tag "stig_id": "SRG-APP-000095-WSR-000056"
  tag "fix_id": "F-47071r2_fix"
  tag "cci": ["CCI-000130"]
  tag "nist": ["AU-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if the web server contains sufficient information to establish
what type of event occurred.

Request a user access the hosted applications, and verify sufficient
information is recorded.

If sufficient information is not logged, this is a finding."
  tag "fix": "Configure the web server to record sufficient information to
establish what type of events occurred."
end

control "V-41613" do
  title "The web server must produce log records containing sufficient
information to establish when (date and time) events occurred."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct order of the events that occurred is important
during forensic analysis. Events that appear harmless by themselves might be
flagged as a potential threat when properly viewed in sequence. By also
establishing the event date and time, an event can be properly viewed with an
enterprise tool to fully see a possible threat in its entirety.

    Without sufficient information establishing when the log event occurred,
investigation into the cause of event is severely hindered. Log record content
that may be necessary to satisfy the requirement of this control includes, but
is not limited to, time stamps, source and destination IP addresses,
user/process identifiers, event descriptions, application-specific events,
success/fail indications, file names involved, access control, or flow control
rules invoked.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000096-WSR-000057"
  tag "gid": "V-41613"
  tag "rid": "SV-54190r3_rule"
  tag "stig_id": "SRG-APP-000096-WSR-000057"
  tag "fix_id": "F-47072r2_fix"
  tag "cci": ["CCI-000131"]
  tag "nist": ["AU-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the web server is configured to generate a date
and time for each logged event.

Request a user access the hosted application and generate logable events, and
then review the logs to determine if the date and time are included in the log
event data.

If the date and time are not included, this is a finding."
  tag "fix": "Configure the web server to log date and time with the event."
end

control "V-41614" do
  title "The web server must produce log records containing sufficient
information to establish where within the web server the events occurred."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct location or process within the web server where
the events occurred is important during forensic analysis. Correctly
determining the web service, plug-in, or module will add information to the
overall reconstruction of the logged event. For example, an event that occurred
during communication to a cgi module might be handled differently than an event
that occurred during a communication session to a user.

    Without sufficient information establishing where the log event occurred
within the web server, investigation into the cause of event is severely
hindered. Log record content that may be necessary to satisfy the requirement
of this control includes, but is not limited to, time stamps, source and
destination IP addresses, user/process identifiers, event descriptions,
application-specific events, success/fail indications, file names involved,
access control, or flow control rules invoked.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000097-WSR-000058"
  tag "gid": "V-41614"
  tag "rid": "SV-54191r3_rule"
  tag "stig_id": "SRG-APP-000097-WSR-000058"
  tag "fix_id": "F-47073r2_fix"
  tag "cci": ["CCI-000132"]
  tag "nist": ["AU-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the web server is configured to generate
sufficient information to resolve in which process within the web server the
log event occurred.

Request a user access the hosted application and generate logable events, and
then review the logs to determine if the process of the event within the web
server can be established.

If it cannot be determined where the event occurred, this is a finding."
  tag "fix": "Configure the web server to generate enough information to
determine in what process within the web server the log event occurred."
end

control "V-41615" do
  title "The web server must produce log records containing sufficient
information to establish the source of events."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct source, e.g. source IP, of the events is important
during forensic analysis. Correctly determining the source will add information
to the overall reconstruction of the logable event. By determining the source
of the event correctly, analysis of the enterprise can be undertaken to
determine if the event compromised other assets within the enterprise.

    Without sufficient information establishing the source of the logged event,
investigation into the cause of event is severely hindered. Log record content
that may be necessary to satisfy the requirement of this control includes, but
is not limited to, time stamps, source and destination IP addresses,
user/process identifiers, event descriptions, application-specific events,
success/fail indications, file names involved, access control, or flow control
rules invoked.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000098-WSR-000059"
  tag "gid": "V-41615"
  tag "rid": "SV-54192r3_rule"
  tag "stig_id": "SRG-APP-000098-WSR-000059"
  tag "fix_id": "F-47074r2_fix"
  tag "cci": ["CCI-000133"]
  tag "nist": ["AU-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the web server is configured to generate
sufficient information to resolve the source, e.g. source IP, of the log event.

Request a user access the hosted application and generate logable events, and
then review the logs to determine if the source of the event can be established.

If the source of the event cannot be determined, this is a finding."
  tag "fix": "Configure the web server to generate the source of each logable
event."
end

control "V-41616" do
  title "A web server, behind a load balancer or proxy server, must produce log
records containing the client IP information as the source and destination and
not the load balancer or proxy IP information with each event."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct source, e.g. source IP, of the events is important
during forensic analysis. Correctly determining the source of events will add
information to the overall reconstruction of the logable event. By determining
the source of the event correctly, analysis of the enterprise can be undertaken
to determine if events tied to the source occurred in other areas within the
enterprise.

    A web server behind a load balancer or proxy server, when not configured
correctly, will record the load balancer or proxy server as the source of every
logable event. When looking at the information forensically, this information
is not helpful in the investigation of events. The web server must record with
each event the client source of the event.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000098-WSR-000060"
  tag "gid": "V-41616"
  tag "rid": "SV-54193r3_rule"
  tag "stig_id": "SRG-APP-000098-WSR-000060"
  tag "fix_id": "F-47075r2_fix"
  tag "cci": ["CCI-000133"]
  tag "nist": ["AU-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the deployment configuration to determine if the web
server is sitting behind a proxy server. If the web server is not sitting
behind a proxy server, this finding is NA.

If the web server is behind a proxy server, review the documentation and
deployment configuration to determine if the web server is configured to
generate sufficient information to resolve the source, e.g. source IP, of the
logged event and not the proxy server.

Request a user access the hosted application through the proxy server and
generate logable events, and then review the logs to determine if the source of
the event can be established.

If the source of the event cannot be determined, this is a finding."
  tag "fix": "Configure the web server to generate the client source, not the
load balancer or proxy server, of each logable event."
end

control "V-41617" do
  title "The web server must produce log records that contain sufficient
information to establish the outcome (success or failure) of events."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the success or failure of an event is important during
forensic analysis. Correctly determining the outcome will add information to
the overall reconstruction of the logable event. By determining the success or
failure of the event correctly, analysis of the enterprise can be undertaken to
determine if events tied to the event occurred in other areas within the
enterprise.

    Without sufficient information establishing the success or failure of the
logged event, investigation into the cause of event is severely hindered. The
success or failure also provides a means to measure the impact of an event and
help authorized personnel to determine the appropriate response. Log record
content that may be necessary to satisfy the requirement of this control
includes, but is not limited to, time stamps, source and destination IP
addresses, user/process identifiers, event descriptions, application-specific
events, success/fail indications, file names involved, access control, or flow
control rules invoked.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000099-WSR-000061"
  tag "gid": "V-41617"
  tag "rid": "SV-54194r3_rule"
  tag "stig_id": "SRG-APP-000099-WSR-000061"
  tag "fix_id": "F-47076r2_fix"
  tag "cci": ["CCI-000134"]
  tag "nist": ["AU-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the web server is configured to generate the
outcome (success or failure) of the event.

Request a user access the hosted application and generate logable events, and
then review the logs to determine if the outcome of the event can be
established.

If the outcome of the event cannot be determined, this is a finding."
  tag "fix": "Configure the web server to generate the outcome, success or
failure, as part of each logable event."
end

control "V-41620" do
  title "The web server must produce log records containing sufficient
information to establish the identity of any user/subject or process associated
with an event."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Determining user accounts, processes running on behalf of the user, and
running process identifiers also enable a better understanding of the overall
event. User tool identification is also helpful to determine if events are
related to overall user access or specific client tools.

    Log record content that may be necessary to satisfy the requirement of this
control includes: time stamps, source and destination addresses, user/process
identifiers, event descriptions, success/fail indications, file names involved,
and access control or flow control rules invoked.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000100-WSR-000064"
  tag "gid": "V-41620"
  tag "rid": "SV-54197r3_rule"
  tag "stig_id": "SRG-APP-000100-WSR-000064"
  tag "fix_id": "F-47079r2_fix"
  tag "cci": ["CCI-001487"]
  tag "nist": ["AU-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the web server can generate log data containing
the user/subject identity.

Request a user access the hosted application and generate logable events, and
verify the events contain the user/subject or process identity.

If the identity is not part of the log record, this is a finding."
  tag "fix": "Configure the web server to include the user/subject identity or
process as part of each log record."
end

control "V-41668" do
  title "The web server must use the internal system clock to generate time
stamps for log records."
  desc  "Without an internal clock used as the reference for the time stored on
each event to provide a trusted common reference for the time, forensic
analysis would be impeded. Determining the correct time a particular event
occurred on the web server is critical when conducting forensic analysis and
investigating system events.

    If the internal clock is not used, the web server may not be able to
provide time stamps for log messages. The web server can use the capability of
an operating system or purpose-built module for this purpose.

    Time stamps generated by the web server shall include both date and time.
The time may be expressed in Coordinated Universal Time (UTC), a modern
continuation of Greenwich Mean Time (GMT), or local time with an offset from
UTC.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000116-WSR-000066"
  tag "gid": "V-41668"
  tag "rid": "SV-54245r3_rule"
  tag "stig_id": "SRG-APP-000116-WSR-000066"
  tag "fix_id": "F-47127r2_fix"
  tag "cci": ["CCI-000159"]
  tag "nist": ["AU-8 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the internal system clock is used for date and
time stamps. If this is not feasible, an alternative workaround is to take an
action that generates an entry in the log and then immediately query the
operating system for the current time. A reasonable match between the two times
will suffice as evidence that the system is using the internal clock for date
and time stamps.

If the web server does not use the internal system clock to generate time
stamps, this is a finding."
  tag "fix": "Configure the web server to use internal system clocks to
generate date and time stamps for log records."
end

control "V-41670" do
  title "Web server log files must only be accessible by privileged users."
  desc  "Log data is essential in the investigation of events. If log data were
to become compromised, then competent forensic analysis and discovery of the
true source of potentially malicious system activity would be difficult, if not
impossible, to achieve. In addition, access to log records provides information
an attacker could potentially use to their advantage since each event record
might contain communication ports, protocols, services, trust relationships,
user names, etc.

    The web server must protect the log data from unauthorized read, write,
copy, etc. This can be done by the web server if the web server is also doing
the logging function. The web server may also use an external log system. In
either case, the logs must be protected from access by non-privileged users.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000118-WSR-000068"
  tag "gid": "V-41670"
  tag "rid": "SV-54247r3_rule"
  tag "stig_id": "SRG-APP-000118-WSR-000068"
  tag "fix_id": "F-47129r2_fix"
  tag "cci": ["CCI-000162"]
  tag "nist": ["AU-9", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
settings to determine if the web server logging features protect log
information from unauthorized access.

Review file system settings to verify the log files have secure file
permissions.

If the web server log files are not protected from unauthorized access, this is
a finding."
  tag "fix": "Configure the web server log files so unauthorized access of log
information is not possible."
end

control "V-41671" do
  title "The log information from the web server must be protected from
unauthorized modification."
  desc  "Log data is essential in the investigation of events. The accuracy of
the information is always pertinent. Information that is not accurate does not
help in the revealing of potential security risks and may hinder the early
discovery of a system compromise. One of the first steps an attacker will
undertake is the modification or deletion of log records to cover his tracks
and prolong discovery.

    The web server must protect the log data from unauthorized modification.
This can be done by the web server if the web server is also doing the logging
function. The web server may also use an external log system. In either case,
the logs must be protected from modification by non-privileged users.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000119-WSR-000069"
  tag "gid": "V-41671"
  tag "rid": "SV-54248r3_rule"
  tag "stig_id": "SRG-APP-000119-WSR-000069"
  tag "fix_id": "F-47130r3_fix"
  tag "cci": ["CCI-000163"]
  tag "nist": ["AU-9", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
settings to determine if the web server logging features protect log
information from unauthorized modification.

Review file system settings to verify the log files have secure file
permissions.

If the web server log files are not protected from unauthorized modification,
this is a finding."
  tag "fix": "Configure the web server log files so unauthorized modification
of log information is not possible."
end

control "V-41672" do
  title "The log information from the web server must be protected from
unauthorized deletion."
  desc  "Log data is essential in the investigation of events. The accuracy of
the information is always pertinent. Information that is not accurate does not
help in the revealing of potential security risks and may hinder the early
discovery of a system compromise. One of the first steps an attacker will
undertake is the modification or deletion of audit records to cover his tracks
and prolong discovery.

    The web server must protect the log data from unauthorized deletion. This
can be done by the web server if the web server is also doing the logging
function. The web server may also use an external log system. In either case,
the logs must be protected from deletion by non-privileged users.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000120-WSR-000070"
  tag "gid": "V-41672"
  tag "rid": "SV-54249r3_rule"
  tag "stig_id": "SRG-APP-000120-WSR-000070"
  tag "fix_id": "F-47131r2_fix"
  tag "cci": ["CCI-000164"]
  tag "nist": ["AU-9", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
settings to determine if the web server logging features protect log
information from unauthorized deletion.

Review file system settings to verify the log files have secure file
permissions.

If the web server log files are not protected from unauthorized deletion, this
is a finding."
  tag "fix": "Configure the web server log files so unauthorized deletion of
log information is not possible."
end

control "V-41674" do
  title "The log data and records from the web server must be backed up onto a
different system or media."
  desc  "Protection of log data includes assuring log data is not accidentally
lost or deleted. Backing up log records to an unrelated system or onto separate
media than the system the web server is actually running on helps to assure
that, in the event of a catastrophic system failure, the log records will be
retained."
  impact 0.5
  tag "gtitle": "SRG-APP-000125-WSR-000071"
  tag "gid": "V-41674"
  tag "rid": "SV-54251r3_rule"
  tag "stig_id": "SRG-APP-000125-WSR-000071"
  tag "fix_id": "F-47133r3_fix"
  tag "cci": ["CCI-001348"]
  tag "nist": ["AU-9 (2)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if the web server log records are backed up onto an unrelated
system or media than the system being logged.

If the web server logs are not backed up onto a different system or media than
the system being logged, this is a finding."
  tag "fix": "Configure the web server logs to be backed up onto a different
system or media other than the system being logged."
end

control "V-41684" do
  title "Expansion modules must be fully reviewed, tested, and signed before
they can exist on a production web server."
  desc  "In the case of a production web server, areas for content development
and testing will not exist, as this type of content is only permissible on a
development website.  The process of developing on a functional production
website entails a degree of trial and error and repeated testing.  This process
is often accomplished in an environment where debugging, sequencing, and
formatting of content are the main goals.  The opportunity for a malicious user
to obtain files that reveal business logic and login schemes is high in this
situation.  The existence of such immature content on a web server represents a
significant security risk that is totally avoidable.

    The web server must enforce, internally or through an external utility, the
signing of modules before they are implemented into a production environment.
By signing modules, the author guarantees that the module has been reviewed and
tested before production implementation.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000131-WSR-000073"
  tag "gid": "V-41684"
  tag "rid": "SV-54261r3_rule"
  tag "stig_id": "SRG-APP-000131-WSR-000073"
  tag "fix_id": "F-47143r2_fix"
  tag "cci": ["CCI-001749"]
  tag "nist": ["CM-5 (3)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if web server modules are fully tested before implementation in the
production environment.

Review the web server for modules identified as test, debug, or backup and that
cannot be reached through the hosted application.

Review the web server to see if the web server or an external utility is in use
to enforce the signing of modules before they are put into a production
environment.

If development and testing is taking place on the production web server or
modules are put into production without being signed, this is a finding."
  tag "fix": "Configure the web server to enforce, internally or through an
external utility, the review, testing and signing of modules before
implementation into the production environment."
end

control "V-41693" do
  title "The web server must only contain services and functions necessary for
operation."
  desc  "A web server can provide many features, services, and processes. Some
of these may be deemed unnecessary or too unsecure to run on a production DoD
system.

    The web server must provide the capability to disable, uninstall, or
deactivate functionality and services that are deemed to be non-essential to
the web server mission or can adversely impact server performance.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000075"
  tag "gid": "V-41693"
  tag "rid": "SV-54270r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000075"
  tag "fix_id": "F-47152r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if web server features, services, and processes are installed that
are not needed for hosted application deployment.

If excessive features, services, and processes are installed, this is a
finding."
  tag "fix": "Uninstall or deactivate features, services, and processes not
needed by the web server for operation."
end

control "V-41694" do
  title "The web server must not be a proxy server."
  desc  "A web server should be primarily a web server or a proxy server but
not both, for the same reasons that other multi-use servers are not
recommended.  Scanning for web servers that will also proxy requests into an
otherwise protected network is a very common attack making the attack
anonymous."
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000076"
  tag "gid": "V-41694"
  tag "rid": "SV-54271r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000076"
  tag "fix_id": "F-47153r3_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if the web server is also a proxy server.

If the web server is also acting as a proxy server, this is a finding."
  tag "fix": "Uninstall any proxy services, modules, and libraries that are
used by the web server to act as a proxy server.

Verify all configuration changes are made to assure the web server is no longer
acting as a proxy server in any manner."
end

control "V-41695" do
  title "The web server must provide install options to exclude the
installation of documentation, sample code, example applications, and
tutorials."
  desc  "Web server documentation, sample code, example applications, and
tutorials may be an exploitable threat to a web server because this type of
code has not been evaluated and approved. A production web server must only
contain components that are operationally necessary (e.g., compiled code,
scripts, web-content, etc.).

    Any documentation, sample code, example applications, and tutorials must be
removed from a production web server. To make certain that the documentation
and code are not installed or uninstalled completely; the web server must offer
an option as part of the installation process to exclude these packages or to
uninstall the packages if necessary.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000077"
  tag "gid": "V-41695"
  tag "rid": "SV-54272r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000077"
  tag "fix_id": "F-47154r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the web server contains documentation, sample
code, example applications, or tutorials.

Verify the web server install process also offers an option to exclude these
elements from installation and provides an uninstall option for their removal.

If web server documentation, sample code, example applications, or tutorials
are installed or the web server install process does not offer an option to
exclude these elements from installation, this is a finding."
  tag "fix": "Use the web server uninstall facility or manually remove any
documentation, sample code, example applications, and tutorials."
end

control "V-41696" do
  title "Web server accounts not utilized by installed features (i.e., tools,
utilities, specific services, etc.) must not be created and must be deleted
when the web server feature is uninstalled."
  desc  "When accounts used for web server features such as documentation,
sample code, example applications, tutorials, utilities, and services are
created even though the feature is not installed, they become an exploitable
threat to a web server.

    These accounts become inactive, are not monitored through regular use, and
passwords for the accounts are not created or updated. An attacker, through
very little effort, can use these accounts to gain access to the web server and
begin investigating ways to elevate the account privileges.

    The accounts used for web server features not installed must not be created
and must be deleted when these features are uninstalled.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000078"
  tag "gid": "V-41696"
  tag "rid": "SV-54273r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000078"
  tag "fix_id": "F-47155r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation to determine the user
accounts created when particular features are installed.

Verify the deployed configuration to determine which features are installed
with the web server.

If any accounts exist that are not used by the installed features, this is a
finding."
  tag "fix": "Use the web server uninstall facility or manually remove the user
accounts not used by the installed web server features."
end

control "V-41698" do
  title "The web server must provide install options to exclude installation of
utility programs, services, plug-ins, and modules not necessary for operation."
  desc  "Just as running unneeded services and protocols is a danger to the web
server at the lower levels of the OSI model, running unneeded utilities and
programs is also a danger at the application layer of the OSI model. Office
suites, development tools, and graphical editors are examples of such programs
that are troublesome.

    Individual productivity tools have no legitimate place or use on an
enterprise, production web server and they are also prone to their own security
risks. The web server installation process must provide options allowing the
installer to choose which utility programs, services, and modules are to be
installed or removed. By having a process for installation and removal, the web
server is guaranteed to be in a more stable and secure state than if these
services and programs were installed and removed manually.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000080"
  tag "gid": "V-41698"
  tag "rid": "SV-54275r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000080"
  tag "fix_id": "F-47157r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine which web server utilities, services, and modules
are installed. Verify these options are essential to the operation of the web
server. Also, confirm the web server install process offers an option to
exclude these utilities, services, and modules from installation that are not
needed for operation and that there is an uninstall option for their removal.

If there are more utilities, services, or modules installed than are needed for
the operation of the web server or the web server does not provide an install
facility to customize installation, this is a finding."
  tag "fix": "Use the web server uninstall facility or manually remove any
utility programs, services, or modules not needed by the web server for
operation."
end

control "V-41699" do
  title "The web server must have Multipurpose Internet Mail Extensions (MIME)
that invoke OS shell programs disabled."
  desc  "Controlling what a user of a hosted application can access is part of
the security posture of the web server. Any time a user can access more
functionality than is needed for the operation of the hosted application poses
a security issue. A user with too much access can view information that is not
needed for the user's job role, or the user could use the function in an
unintentional manner.

    A MIME tells the web server what type of program various file types and
extensions are and what external utilities or programs are needed to execute
the file type.

    A shell is a program that serves as the basic interface between the user
and the operating system, so hosted application users must not have access to
these programs. Shell programs may execute shell escapes and can then perform
unauthorized activities that could damage the security posture of the web
server.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000081"
  tag "gid": "V-41699"
  tag "rid": "SV-54276r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000081"
  tag "fix_id": "F-47158r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the OS shell is accessible by any MIME types that
are enabled.

If a user of the web server can invoke OS shell programs, this is a finding."
  tag "fix": "Configure the web server to disable all MIME types that invoke OS
shell programs."
end

control "V-41700" do
  title "The web server must allow the mappings to unused and vulnerable
scripts to be removed."
  desc  "Scripts allow server side processing on behalf of the hosted
application user or as processes needed in the implementation of hosted
applications. Removing scripts not needed for application operation or deemed
vulnerable helps to secure the web server.

    To assure scripts are not added to the web server and run maliciously,
those script mappings that are not needed or used by the web server for hosted
application operation must be removed.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000082"
  tag "gid": "V-41700"
  tag "rid": "SV-54277r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000082"
  tag "fix_id": "F-47159r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine what script mappings are available.

Review the scripts used by the web server and the hosted applications.

If there are script mappings in use that are not used by the web server or
hosted applications for operation, this is a finding."
  tag "fix": "Remove script mappings that are not needed for web server and
hosted application operation."
end

control "V-41701" do
  title "The web server must have resource mappings set to disable the serving
of certain file types."
  desc  "Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and which files cannot be served to a
user, the web server could deliver to a user web server configuration files,
log files, password files, etc.

    The web server must only allow hosted application file types to be served
to a user and all other types must be disabled.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000083"
  tag "gid": "V-41701"
  tag "rid": "SV-54278r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000083"
  tag "fix_id": "F-47160r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine what types of files are being used for the hosted
applications.

If the web server is configured to allow other file types not associated with
the hosted application, especially those associated with logs, configuration
files, passwords, etc., this is a finding."
  tag "fix": "Configure the web server to only serve file types to the user
that are needed by the hosted applications.  All other file types must be
disabled."
end

control "V-41702" do
  title "The web server must have Web Distributed Authoring (WebDAV) disabled."
  desc  "A web server can be installed with functionality that, just by its
nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to
the HTTP protocol that, when developed, was meant to allow users to create,
change, and move documents on a server, typically a web server or web share.
Allowing this functionality, development, and deployment is much easier for web
authors.

    WebDAV is not widely used and has serious security concerns because it may
allow clients to modify unauthorized files on the web server.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000085"
  tag "gid": "V-41702"
  tag "rid": "SV-54279r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000085"
  tag "fix_id": "F-47161r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if Web Distributed Authoring (WebDAV) is enabled.

If WebDAV is enabled, this is a finding."
  tag "fix": "Configure the web server to disable Web Distributed Authoring."
end

control "V-41703" do
  title "The web server must protect system resources and privileged operations
from hosted applications."
  desc  "A web server may host one too many applications.  Each application
will need certain system resources and privileged operations to operate
correctly.  The web server must be configured to contain and control the
applications and protect the system resources and privileged operations from
those not needed by the application for operation.

    Limiting the application will confine the potential harm a compromised
application could cause to a system.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000086"
  tag "gid": "V-41703"
  tag "rid": "SV-54280r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000086"
  tag "fix_id": "F-47162r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine the access to server resources given to hosted applications.

If hosted applications have access to more system resources than needed for
operation, this is a finding."
  tag "fix": "Configure the privileges given to hosted applications to the
minimum required for application operation."
end

control "V-41704" do
  title "Users and scripts running on behalf of users must be contained to the
document root or home directory tree of the web server."
  desc  "A web server is designed to deliver content and execute scripts or
applications on the request of a client or user.  Containing user requests to
files in the directory tree of the hosted web application and limiting the
execution of scripts and applications guarantees that the user is not accessing
information protected outside the application's realm.

    The web server must also prohibit users from jumping outside the hosted
application directory tree through access to the user's home directory,
symbolic links or shortcuts, or through search paths for missing files.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000087"
  tag "gid": "V-41704"
  tag "rid": "SV-54281r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000087"
  tag "fix_id": "F-47163r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine where the document root or home directory for each application hosted
by the web server is located.

Verify that users of the web server applications, and any scripts running on
the user's behalf, are contained to each application's domain.

If users of the web server applications, and any scripts running on the user's
behalf, are not contained, this is a finding."
  tag "fix": "Configure the web server to contain users and scripts to each
hosted application's domain."
end

control "V-41706" do
  title "The web server must be configured to use a specified IP address and
port."
  desc  "The web server must be configured to listen on a specified IP address
and port.  Without specifying an IP address and port for the web server to
utilize, the web server will listen on all IP addresses available to the
hosting server.  If the web server has multiple IP addresses, i.e., a
management IP address, the web server will also accept connections on the
management IP address.

    Accessing the hosted application through an IP address normally used for
non-application functions opens the possibility of user access to resources,
utilities, files, ports, and protocols that are protected on the desired
application IP address.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000142-WSR-000089"
  tag "gid": "V-41706"
  tag "rid": "SV-54283r3_rule"
  tag "stig_id": "SRG-APP-000142-WSR-000089"
  tag "fix_id": "F-47165r2_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine whether the web server is configured to listen on a
specified IP address and port.

Request a client user try to access the web server on any other available IP
addresses on the hosting hardware.

If an IP address is not configured on the web server or a client can reach the
web server on other IP addresses assigned to the hosting hardware, this is a
finding."
  tag "fix": "Configure the web server to only listen on a specified IP address
and port."
end

control "V-41730" do
  title "The web server must perform RFC 5280-compliant certification path
validation."
  desc  "A certificate's certification path is the path from the end entity
certificate to a trusted root certification authority (CA). Certification path
validation is necessary for a relying party to make an informed decision
regarding acceptance of an end entity certificate. Certification path
validation includes checks such as certificate issuer trust, time validity and
revocation status for each certificate in the certification path. Revocation
status information for CA and subject certificates in a certification path is
commonly provided via certificate revocation lists (CRLs) or online certificate
status protocol (OCSP) responses."
  impact 0.5
  tag "gtitle": "SRG-APP-000175-WSR-000095"
  tag "gid": "V-41730"
  tag "rid": "SV-54307r3_rule"
  tag "stig_id": "SRG-APP-000175-WSR-000095"
  tag "fix_id": "F-47189r4_fix"
  tag "cci": ["CCI-000185"]
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether the web server provides PKI functionality that validates
certification paths in accordance with RFC 5280. If PKI is not being used, this
is NA.

If the web server is using PKI, but it does not perform this requirement, this
is a finding."
  tag "fix": "Configure the web server to validate certificates in accordance
with RFC 5280."
end

control "V-41731" do
  title "Only authenticated system administrators or the designated PKI Sponsor
for the web server must have access to the web servers private key."
  desc  "The web server's private key is used to prove the identity of the
server to clients and securely exchange the shared secret key used to encrypt
communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an
authorized server and decrypt the SSL traffic between a client and the web
server.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000176-WSR-000096"
  tag "gid": "V-41731"
  tag "rid": "SV-54308r3_rule"
  tag "stig_id": "SRG-APP-000176-WSR-000096"
  tag "fix_id": "F-47190r2_fix"
  tag "cci": ["CCI-000186"]
  tag "nist": ["IA-5 (2) (b)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If the web server does not have a private key, this is N/A.

Review the web server documentation and deployed configuration to determine
whether only authenticated system administrators and the designated PKI Sponsor
for the web server can access the web server private key.

If the private key is accessible by unauthenticated or unauthorized users, this
is a finding."
  tag "fix": "Configure the web server to ensure only authenticated and
authorized users can access the web server's private key."
end

control "V-41738" do
  title "The web server must encrypt passwords during transmission."
  desc  "Data used to authenticate, especially passwords, needs to be protected
at all times, and encryption is the standard method for protecting
authentication data during transmission. Data used to authenticate can be
passed to and from the web server for many reasons.

    Examples include data passed from a user to the web server through an HTTPS
connection for authentication, the web server authenticating to a backend
database for data retrieval and posting, and the web server authenticating to a
clustered web server manager for an update.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000172-WSR-000104"
  tag "gid": "V-41738"
  tag "rid": "SV-54315r3_rule"
  tag "stig_id": "SRG-APP-000172-WSR-000104"
  tag "fix_id": "F-47197r2_fix"
  tag "cci": ["CCI-000197"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether passwords are being passed to or from the web server.

If the transmission of passwords is not encrypted, this is a finding."
  tag "fix": "Configure the web server to encrypt the transmission passwords."
end

control "V-41745" do
  title "The web server must use cryptographic modules that meet the
requirements of applicable federal laws, Executive Orders, directives,
policies, regulations, standards, and guidance when encrypting stored data."
  desc  "Encryption is only as good as the encryption modules utilized.
Unapproved cryptographic module algorithms cannot be verified, and cannot be
relied upon to provide confidentiality or integrity, and DoD data may be
compromised due to weak algorithms.

    FIPS 140-2 is the current standard for validating cryptographic modules and
NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based
encryption modules.

    The web server must provide FIPS-compliant encryption modules when storing
encrypted data and configuration settings.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000179-WSR-000110"
  tag "gid": "V-41745"
  tag "rid": "SV-54322r3_rule"
  tag "stig_id": "SRG-APP-000179-WSR-000110"
  tag "fix_id": "F-47204r2_fix"
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review web server documentation and deployed configuration to
determine whether the encryption modules utilized for storage of data are FIPS
140-2 compliant.

Reference the following NIST site to identify validated encryption modules:

http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm

If the encryption modules used for storage of data are not FIPS 140-2
validated, this is a finding."
  tag "fix": "Configure the web server to utilize FIPS 140-2 approved
encryption modules when the web server is storing data."
end

control "V-41746" do
  title "The web server must use cryptographic modules that meet the
requirements of applicable federal laws, Executive Orders, directives,
policies, regulations, standards, and guidance for such authentication."
  desc  "Encryption is only as good as the encryption modules utilized.
Unapproved cryptographic module algorithms cannot be verified and cannot be
relied upon to provide confidentiality or integrity, and DoD data may be
compromised due to weak algorithms.

    FIPS 140-2 is the current standard for validating cryptographic modules and
NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based
encryption modules.

    The web server must provide FIPS-compliant encryption modules when
authenticating users and processes.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000179-WSR-000111"
  tag "gid": "V-41746"
  tag "rid": "SV-54323r3_rule"
  tag "stig_id": "SRG-APP-000179-WSR-000111"
  tag "fix_id": "F-47205r2_fix"
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review web server documentation and deployed configuration to
determine whether the encryption modules utilized for authentication are FIPS
140-2 compliant.  Reference the following NIST site to identify validated
encryption modules:
http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm

If the encryption modules used for authentication are not FIPS 140-2 validated,
this is a finding."
  tag "fix": "Configure the web server to utilize FIPS 140-2 approved
encryption modules when authenticating users and processes."
end

control "V-41794" do
  title "The web server must separate the hosted applications from hosted web
server management functionality."
  desc  "The separation of user functionality from web server management can be
accomplished by moving management functions to a separate IP address or port.
To further separate the management functions, separate authentication methods
and certificates should be used.

    By moving the management functionality, the possibility of accidental
discovery of the management functions by non-privileged users during hosted
application use is minimized.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000211-WSR-000129"
  tag "gid": "V-41794"
  tag "rid": "SV-54371r3_rule"
  tag "stig_id": "SRG-APP-000211-WSR-000129"
  tag "fix_id": "F-47253r2_fix"
  tag "cci": ["CCI-001082"]
  tag "nist": ["SC-2", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether hosted application functionality is separated from web
server management functions.

If the functions are not separated, this is a finding."
  tag "fix": "Configure the web server to separate the hosted applications from
web server management functionality."
end

control "V-41807" do
  title "The web server must generate unique session identifiers that cannot be
reliably reproduced."
  desc  "Communication between a client and the web server is done using the
HTTP protocol, but HTTP is a stateless protocol. In order to maintain a
connection or session, a web server will generate a session identifier (ID) for
each client session when the session is initiated. The session ID allows the
web server to track a user session and, in many cases, the user, if the user
previously logged into a hosted application.

    By being able to guess session IDs, an attacker can easily perform a
man-in-the-middle attack. To truly generate random session identifiers that
cannot be reproduced, the web server session ID generator, when used twice with
the same input criteria, must generate an unrelated random ID.

    The session ID generator also needs to be a FIPS 140-2 approved generator.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000224-WSR-000136"
  tag "gid": "V-41807"
  tag "rid": "SV-54384r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000136"
  tag "fix_id": "F-47266r2_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to verify that random and unique session identifiers are generated.

Access the web server ID generator function and generate two IDs using the same
input.

If the web server is not configured to generate random and unique session
identifiers, or the ID generator generates the same ID for the same input, this
is a finding."
  tag "fix": "Configure the web server to generate random and unique session
identifiers that cannot be reliably reproduced."
end

control "V-41808" do
  title "The web server must generate a session ID long enough that it cannot
be guessed through brute force."
  desc  "Generating a session identifier (ID) that is not easily guessed
through brute force is essential to deter several types of session attacks.  By
knowing the session ID, an attacker can hijack a user session that has already
been user authenticated by the hosted application.  The attacker does not need
to guess user identifiers and passwords or have a secure token since the user
session has already been authenticated.

    Generating session IDs that are at least 128 bits (16 bytes) in length will
cause an attacker to take a large amount of time and resources to guess,
reducing the likelihood of an attacker guessing a session ID.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000224-WSR-000137"
  tag "gid": "V-41808"
  tag "rid": "SV-54385r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000137"
  tag "fix_id": "F-47267r2_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to see how long the generated session identifiers are.

If the web server is not configured to generate session identifiers that are at
least 128 bits (16 bytes) in length, this is a finding."
  tag "fix": "Configure the web server to generate session identifiers that are
at least 128 bits in length."
end

control "V-41809" do
  title "The web server must generate a session ID using as much of the
character set as possible to reduce the risk of brute force."
  desc  "Generating a session identifier (ID) that is not easily guessed
through brute force is essential to deter several types of session attacks. By
knowing the session ID, an attacker can hijack a user session that has already
been user-authenticated by the hosted application. The attacker does not need
to guess user identifiers and passwords or have a secure token since the user
session has already been authenticated.

    By generating session IDs that contain as much of the character set as
possible, i.e., A-Z, a-z, and 0-9, the session ID becomes exponentially harder
to guess.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000224-WSR-000138"
  tag "gid": "V-41809"
  tag "rid": "SV-54386r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000138"
  tag "fix_id": "F-47268r2_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine what characters are used in generating session IDs.

If the web server is not configured to use at least A-Z, a-z, and 0-9 to
generate session identifiers, this is a finding."
  tag "fix": "Configure the web server to use at least A-Z, a-z, and 0-9 to
generate session IDs."
end

control "V-41810" do
  title "The web server must generate unique session identifiers with definable
entropy."
  desc  "Generating a session identifier (ID) that is not easily guessed
through brute force is essential to deter several types of session attacks. By
knowing the session ID, an attacker can hijack a user session that has already
been user authenticated by the hosted application. The attacker does not need
to guess user identifiers and passwords or have a secure token since the user
session has already been authenticated.

    Random and unique session IDs are the opposite of sequentially generated
session IDs, which can be easily guessed by an attacker. Random session
identifiers help to reduce predictability of said identifiers. The session ID
must be unpredictable (random enough) to prevent guessing attacks, where an
attacker is able to guess or predict the ID of a valid session through
statistical analysis techniques. For this purpose, a good PRNG (Pseudo Random
Number Generator) must be used.

    Unique session IDs address man-in-the-middle attacks, including session
hijacking or insertion of false information into a session. If the attacker is
unable to identify or guess the session information related to pending
application traffic, they will have more difficulty in hijacking the session or
otherwise manipulating valid sessions.

    At least half of a session ID must be created using a definable source of
entropy (PRNG).
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000224-WSR-000139"
  tag "gid": "V-41810"
  tag "rid": "SV-54387r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000139"
  tag "fix_id": "F-47269r2_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to verify that the web server is generating random session IDs with entropy
equal to at least half the session ID length.

If the web server is not configured to generate random session IDs with the
proper amount of entropy, this is a finding."
  tag "fix": "Configure the web server to generate random session IDs with
minimum entropy equal to half the session ID length."
end

control "V-41811" do
  title "The web server must be built to fail to a known safe state if system
initialization fails, shutdown fails, or aborts fail."
  desc  "Determining a safe state for failure and weighing that against a
potential DoS for users depends on what type of application the web server is
hosting. For an application presenting publicly available information that is
not critical, a safe state for failure might be to shut down for any type of
failure; but for an application that presents critical and timely information,
a shutdown might not be the best state for all failures.

    Performing a proper risk analysis of the hosted applications and
configuring the web server according to what actions to take for each failure
condition will provide a known fail safe state for the web server.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000225-WSR-000140"
  tag "gid": "V-41811"
  tag "rid": "SV-54388r3_rule"
  tag "stig_id": "SRG-APP-000225-WSR-000140"
  tag "fix_id": "F-47270r3_fix"
  tag "cci": ["CCI-001190"]
  tag "nist": ["SC-24", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation, deployed configuration,
and risk analysis documentation to determine whether the web server will fail
to known states for system initialization, shutdown, or abort failures.

If the web server will not fail to known state, this is a finding."
  tag "fix": "Configure the web server to fail to the states of operation
during system initialization, shutdown, or abort failures found in the risk
analysis."
end

control "V-41812" do
  title "The web server must provide a clustering capability."
  desc  "The web server may host applications that display information that
cannot be disrupted, such as information that is time-critical or
life-threatening. In these cases, a web server that shuts down or ceases to be
accessible when there is a failure is not acceptable. In these types of cases,
clustering of web servers is used.

    Clustering of multiple web servers is a common approach to providing
fail-safe application availability. To assure application availability, the web
server must provide clustering or some form of failover functionality.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000225-WSR-000141"
  tag "gid": "V-41812"
  tag "rid": "SV-54389r3_rule"
  tag "stig_id": "SRG-APP-000225-WSR-000141"
  tag "fix_id": "F-47271r2_fix"
  tag "cci": ["CCI-001190"]
  tag "nist": ["SC-24", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation, deployed configuration,
and risk analysis documentation to verify that the web server is configured to
provide clustering functionality, if the web server is a high-availability web
server.

If the web server is not a high-availability web server, this finding is NA.

If the web server is not configured to provide clustering or some form of
failover functionality and the web server is a high-availability server, this
is a finding."
  tag "fix": "Configure the web server to provide application failover, or
participate in a web cluster that provides failover for high-availability web
servers."
end

control "V-41815" do
  title "Information at rest must be encrypted using a DoD-accepted algorithm
to protect the confidentiality and integrity of the information."
  desc  "Data at rest is inactive data which is stored physically in any
digital form (e.g., databases, data warehouses, spreadsheets, archives, tapes,
off-site backups, mobile devices, etc.). Data at rest includes, but is not
limited to, archived data, data which is not accessed or changed frequently,
files stored on hard drives, USB thumb drives, files stored on backup tape and
disks, and files stored off-site or on a storage area network.

    While data at rest can reside in many places, data at rest for a web server
is data on the hosting system storage devices. Data stored as a backup on tape
or stored off-site is no longer under the protection measures covered by the
web server.

    There are several pieces of data that the web server uses during operation.
The web server must use an accepted encryption method, such as SHA1, to protect
the confidentiality and integrity of the information.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000231-WSR-000144"
  tag "gid": "V-41815"
  tag "rid": "SV-54392r3_rule"
  tag "stig_id": "SRG-APP-000231-WSR-000144"
  tag "fix_id": "F-47274r2_fix"
  tag "cci": ["CCI-001199"]
  tag "nist": ["SC-28", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to locate where potential data at rest is stored.

Verify that the data is encrypted using a DoD-accepted algorithm to protect the
confidentiality and integrity of the information.

If the data is not encrypted using a DoD-accepted algorithm, this is a finding."
  tag "fix": "Use a DoD-accepted algorithm to encrypt data at rest to protect
the information's confidentiality and integrity."
end

control "V-41818" do
  title "The web server must accept only system-generated session identifiers."
  desc  "Communication between a client and the web server is done using the
HTTP protocol, but HTTP is a stateless protocol. In order to maintain a
connection or session, a web server will generate a session identifier (ID) for
each client session when the session is initiated. The session ID allows the
web server to track a user session and, in many cases, the user, if the user
previously logged into a hosted application.

    When a web server accepts session identifiers that are not generated by the
web server, the web server creates an environment where session hijacking, such
as session fixation, could be used to access hosted applications through
session IDs that have already been authenticated. Forcing the web server to
only accept web server-generated session IDs and to create new session IDs once
a user is authenticated will limit session hijacking.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000223-WSR-000145"
  tag "gid": "V-41818"
  tag "rid": "SV-54395r3_rule"
  tag "stig_id": "SRG-APP-000223-WSR-000145"
  tag "fix_id": "F-47277r3_fix"
  tag "cci": ["CCI-001664"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether the web server accepts session IDs that are not
system-generated.

If the web server does accept non-system-generated session IDs, this is a
finding."
  tag "fix": "Configure the web server to only accept session IDs that are
created by the web server."
end

control "V-41821" do
  title "The web server document directory must be in a separate partition from
the web servers system files."
  desc  "A web server is used to deliver content on the request of a client.
The content delivered to a client must be controlled, allowing only hosted
application files to be accessed and delivered. To allow a client access to
system files of any type is a major security risk that is entirely avoidable.
Obtaining such access is the goal of directory traversal and URL manipulation
vulnerabilities. To facilitate such access by misconfiguring the web document
(home) directory is a serious error. In addition, having the path on the same
drive as the system folder compounds potential attacks such as drive space
exhaustion."
  impact 0.5
  tag "gtitle": "SRG-APP-000233-WSR-000146"
  tag "gid": "V-41821"
  tag "rid": "SV-54398r3_rule"
  tag "stig_id": "SRG-APP-000233-WSR-000146"
  tag "fix_id": "F-47280r2_fix"
  tag "cci": ["CCI-001084"]
  tag "nist": ["SC-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine where the document directory is located for each hosted
application.

If the document directory is not in a separate partition from the web server's
system files, this is a finding."
  tag "fix": "Configure the web server to place the document directories in a
separate partition from the web server system files."
end

control "V-41833" do
  title "The web server must restrict the ability of users to launch Denial of
Service (DoS) attacks against other information systems or networks."
  desc  "A web server can limit the ability of the web server being used in a
DoS attack through several methods. The methods employed will depend upon the
hosted applications and their resource needs for proper operation.

    An example setting that could be used to limit the ability of the web
server being used in a DoS attack is bandwidth throttling.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000246-WSR-000149"
  tag "gid": "V-41833"
  tag "rid": "SV-54410r3_rule"
  tag "stig_id": "SRG-APP-000246-WSR-000149"
  tag "fix_id": "F-47292r2_fix"
  tag "cci": ["CCI-001094"]
  tag "nist": ["SC-5 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether the web server has been configured to limit the ability of
the web server to be used in a DoS attack.

If not, this is a finding."
  tag "fix": "Configure the web server to limit the ability of users to use the
web server in a DoS attack."
end

control "V-41852" do
  title "The web server must limit the character set used for data entry."
  desc  "Invalid user input occurs when a user inserts data or characters into
a hosted application's data entry field and the hosted application is
unprepared to process that data. This results in unanticipated application
behavior, potentially leading to an application compromise. Invalid user input
is one of the primary methods employed when attempting to compromise an
application.

    An attacker can also enter Unicode into hosted applications in an effort to
break out of the document home or root home directory or to bypass security
checks.

    The web server, by defining the character set available for data entry, can
trap efforts to bypass security checks or to compromise an application.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000251-WSR-000157"
  tag "gid": "V-41852"
  tag "rid": "SV-54429r3_rule"
  tag "stig_id": "SRG-APP-000251-WSR-000157"
  tag "fix_id": "F-47311r2_fix"
  tag "cci": ["CCI-001310"]
  tag "nist": ["SI-10", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine what the data set is for data entry.

If the web server does not limit the data set used for data entry, this is a
finding."
  tag "fix": "Configure the web server to only accept the character sets
expected by the hosted applications."
end

control "V-41854" do
  title "Warning and error messages displayed to clients must be modified to
minimize the identity of the web server, patches, loaded modules, and directory
paths."
  desc  "Information needed by an attacker to begin looking for possible
vulnerabilities in a web server includes any information about the web server,
backend systems being accessed, and plug-ins or modules being used.

    Web servers will often display error messages to client users displaying
enough information to aid in the debugging of the error. The information given
back in error messages may display the web server type, version, patches
installed, plug-ins and modules installed, type of code being used by the
hosted application, and any backends being used for data storage.

    This information could be used by an attacker to blueprint what type of
attacks might be successful. The information given to users must be minimized
to not aid in the blueprinting of the web server.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000266-WSR-000159"
  tag "gid": "V-41854"
  tag "rid": "SV-54431r3_rule"
  tag "stig_id": "SRG-APP-000266-WSR-000159"
  tag "fix_id": "F-47313r2_fix"
  tag "cci": ["CCI-001312"]
  tag "nist": ["SI-11 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether the web server offers different modes of operation that
will minimize the identity of the web server, patches, loaded modules, and
directory paths given to clients on error conditions.

If the web server is not configured to minimize the information given to
clients, this is a finding."
  tag "fix": "Configure the web server to minimize the information provided to
the client in warning and error messages."
end

control "V-41855" do
  title "Debugging and trace information used to diagnose the web server must
be disabled."
  desc  "Information needed by an attacker to begin looking for possible
vulnerabilities in a web server includes any information about the web server
and plug-ins or modules being used. When debugging or trace information is
enabled in a production web server, information about the web server, such as
web server type, version, patches installed, plug-ins and modules installed,
type of code being used by the hosted application, and any backends being used
for data storage may be displayed. Since this information may be placed in logs
and general messages during normal operation of the web server, an attacker
does not need to cause an error condition to gain this information."
  impact 0.5
  tag "gtitle": "SRG-APP-000266-WSR-000160"
  tag "gid": "V-41855"
  tag "rid": "SV-54432r3_rule"
  tag "stig_id": "SRG-APP-000266-WSR-000160"
  tag "fix_id": "F-47314r2_fix"
  tag "cci": ["CCI-001312"]
  tag "nist": ["SI-11 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if debugging and trace information are enabled.

If the web server is configured with debugging and trace information enabled,
this is a finding."
  tag "fix": "Configure the web server to minimize the information given to
clients on error conditions by disabling debugging and trace information."
end

control "V-55945" do
  title "The web server must enforce approved authorizations for logical access
to hosted applications and resources in accordance with applicable access
control policies."
  desc  "To control access to sensitive information and hosted applications by
entities that have been issued certificates by DoD-approved PKIs, the web
server must be properly configured to incorporate a means of authorization that
does not simply rely on the possession of a valid certificate for access.
Access decisions must include a verification that the authenticated entity is
permitted to access the information or application. Authorization decisions
must leverage a variety of methods, such as mapping the validated PKI
certificate to an account with an associated set of permissions on the system.
If the web server relied only on the possession of the certificate and did not
map to system roles and privileges, each user would have the same abilities and
roles to make changes to the production system."
  impact 0.5
  tag "gtitle": "SRG-APP-000033-WSR-000169"
  tag "gid": "V-55945"
  tag "rid": "SV-70199r2_rule"
  tag "stig_id": "SRG-APP-000033-WSR-000169"
  tag "fix_id": "F-60823r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "The web server must be configured to perform an authorization
check to verify that the authenticated entity should be granted access to the
requested content.

If the web server does not verify that the authenticated entity is authorized
to access the requested content prior to granting access, this is a finding."
  tag "fix": "Configure the web server to validate the authenticated entity's
authorization to access requested content prior to granting access."
end

control "V-55947" do
  title "Non-privileged accounts on the hosting system must only access web
server security-relevant information and functions through a distinct
administrative account."
  desc  "By separating web server security functions from non-privileged users,
roles can be developed that can then be used to administer the web server.
Forcing users to change from a non-privileged account to a privileged account
when operating on the web server or on security-relevant information forces
users to only operate as a web server administrator when necessary. Operating
in this manner allows for better logging of changes and better forensic
information and limits accidental changes to the web server."
  impact 0.5
  tag "gtitle": "SRG-APP-000340-WSR-000029"
  tag "gid": "V-55947"
  tag "rid": "SV-70201r2_rule"
  tag "stig_id": "SRG-APP-000340-WSR-000029"
  tag "fix_id": "F-60825r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if accounts used for administrative duties of the web server are
separated from non-privileged accounts.

If non-privileged accounts can access web server security-relevant information,
this is a finding."
  tag "fix": "Set up accounts and roles that can be used to perform web server
security-relevant tasks and remove or modify non-privileged account access to
security-relevant tasks."
end

control "V-55949" do
  title "The web server must set an inactive timeout for sessions."
  desc  "Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after a
set period of inactivity, the web server can make certain that those sessions
that are not closed through the user logging out of an application are
eventually closed.

    Acceptable values are 5 minutes for high-value applications, 10 minutes for
medium-value applications, and 20 minutes for low-value applications.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000295-WSR-000134"
  tag "gid": "V-55949"
  tag "rid": "SV-70203r2_rule"
  tag "stig_id": "SRG-APP-000295-WSR-000134"
  tag "fix_id": "F-60827r1_fix"
  tag "cci": ["CCI-002361"]
  tag "nist": ["AC-12", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the hosted applications, web server documentation and
deployed configuration to verify that the web server will close an open session
after a configurable time of inactivity.

If the web server does not close sessions after a configurable time of
inactivity or the amount of time is configured higher than 5 minutes for
high-risk applications, 10 minutes for medium-risk applications, or 20 minutes
for low-risk applications, this is a finding."
  tag "fix": "Configure the web server to close inactive sessions after 5
minutes for high-risk applications, 10 minutes for medium-risk applications, or
20 minutes for low-risk applications."
end

control "V-55951" do
  title "The web server must set an absolute timeout for sessions."
  desc  "Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after an
absolute period of time, the user is forced to re-authenticate guaranteeing the
session is still in use. Enabling an absolute timeout for sessions closes
sessions that are still active. Examples would be a runaway process accessing
the web server or an attacker using a hijacked session to slowly probe the web
server."
  impact 0.5
  tag "gtitle": "SRG-APP-000295-WSR-000012"
  tag "gid": "V-55951"
  tag "rid": "SV-70205r2_rule"
  tag "stig_id": "SRG-APP-000295-WSR-000012"
  tag "fix_id": "F-60829r1_fix"
  tag "cci": ["CCI-002361"]
  tag "nist": ["AC-12", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to verify that the web server is configured to close sessions after an absolute
period of time.

If the web server is not configured to close sessions after an absolute period
of time, this is a finding."
  tag "fix": "Configure the web server to close sessions after an absolute
period of time."
end

control "V-55953" do
  title "Remote access to the web server must follow access policy or work in
conjunction with enterprise tools designed to enforce policy requirements."
  desc  "Remote access to the web server is any access that communicates
through an external, non-organization-controlled network. Remote access can be
used to access hosted applications or to perform management functions.

    A web server can be accessed remotely and must be able to enforce remote
access policy requirements or work in conjunction with enterprise tools
designed to enforce policy requirements.

    Examples of the web server enforcing a remote access policy are
implementing IP filtering rules, using https instead of http for communication,
implementing secure tokens, and validating users.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000315-WSR-000003"
  tag "gid": "V-55953"
  tag "rid": "SV-70207r2_rule"
  tag "stig_id": "SRG-APP-000315-WSR-000003"
  tag "fix_id": "F-60831r2_fix"
  tag "cci": ["CCI-002314"]
  tag "nist": ["AC-17 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server product documentation and deployed
configuration to determine if the server or an enterprise tool is enforcing the
organization's requirements for remote connections.

If the web server is not configured to enforce these requirements and an
enterprise tool is not in place, this is a finding."
  tag "fix": "Configure the web server to enforce the remote access policy or
to work with an enterprise tool designed to enforce the policy."
end

control "V-55955" do
  title "The web server must provide the capability to immediately disconnect
or disable remote access to the hosted applications."
  desc  "During an attack on the web server or any of the hosted applications,
the system administrator may need to disconnect or disable access by users to
stop the attack.

    The web server must provide a capability to disconnect users to a hosted
application without compromising other hosted applications unless deemed
necessary to stop the attack. Methods to disconnect or disable connections are
to stop the application service for a specified hosted application, stop the
web server, or block all connections through web server access list.

    The web server capabilities used to disconnect or disable users from
connecting to hosted applications and the web server must be documented to make
certain that, during an attack, the proper action is taken to conserve
connectivity to any other hosted application if possible and to make certain
log data is conserved for later forensic analysis.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000316-WSR-000170"
  tag "gid": "V-55955"
  tag "rid": "SV-70209r2_rule"
  tag "stig_id": "SRG-APP-000316-WSR-000170"
  tag "fix_id": "F-60833r1_fix"
  tag "cci": ["CCI-002322"]
  tag "nist": ["AC-17 (9)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to make
certain that the web server is configured to allow for the immediate
disconnection or disabling of remote access to hosted applications when
necessary.

If the web server is not capable of or cannot be configured to disconnect or
disable remote access to the hosted applications when necessary, this is a
finding."
  tag "fix": "Configure the web server to provide the capability to immediately
disconnect or disable remote access to the hosted applications."
end

control "V-55957" do
  title "A web server that is part of a web server cluster must route all
remote management through a centrally managed access control point."
  desc  "A web server cluster is a group of independent web servers that are
managed as a single system for higher availability, easier manageability, and
greater scalability. Without having centralized control of the web server
cluster, management of the cluster becomes difficult. It is critical that
remote management of the cluster be done through a designated management system
acting as a single access point."
  impact 0.5
  tag "gtitle": "SRG-APP-000356-WSR-000007"
  tag "gid": "V-55957"
  tag "rid": "SV-70211r2_rule"
  tag "stig_id": "SRG-APP-000356-WSR-000007"
  tag "fix_id": "F-60835r1_fix"
  tag "cci": ["CCI-001844"]
  tag "nist": ["AU-3 (2)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if the web server is part of a cluster.

If the web server is not part of a cluster, then this is NA.

If the web server is part of a cluster and is not centrally managed, then this
is a finding."
  tag "fix": "Configure the web server to be centrally managed."
end

control "V-55959" do
  title "The web server must use a logging mechanism that is configured to
allocate log record storage capacity large enough to accommodate the logging
requirements of the web server."
  desc  "In order to make certain that the logging mechanism used by the web
server has sufficient storage capacity in which to write the logs, the logging
mechanism needs to be able to allocate log record storage capacity.

    The task of allocating log record storage capacity is usually performed
during initial installation of the logging mechanism. The system administrator
will usually coordinate the allocation of physical drive space with the web
server administrator along with the physical location of the partition and
disk. Refer to NIST SP 800-92 for specific requirements on log rotation and
storage dependent on the impact of the web server.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000357-WSR-000150"
  tag "gid": "V-55959"
  tag "rid": "SV-70213r2_rule"
  tag "stig_id": "SRG-APP-000357-WSR-000150"
  tag "fix_id": "F-60837r1_fix"
  tag "cci": ["CCI-001849"]
  tag "nist": ["AU-4", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the web server is using a logging mechanism to
store log records. If a logging mechanism is in use, validate that the
mechanism is configured to use record storage capacity in accordance with
specifications within NIST SP 800-92 for log record storage requirements.

If the web server is not using a logging mechanism, or if the mechanism has not
been configured to allocate log record storage capacity in accordance with NIST
SP 800-92, this is a finding."
  tag "fix": "Configure the web server to use a logging mechanism that is
configured to allocate log record storage capacity in accordance with NIST SP
800-92 log record storage requirements."
end

control "V-55961" do
  title "The web server must restrict inbound connections from nonsecure zones."
  desc  "Remote access to the web server is any access that communicates
through an external, non-organization-controlled network. Remote access can be
used to access hosted applications or to perform management functions.

    A web server can be accessed remotely and must be capable of restricting
access from what the DoD defines as nonsecure zones. Nonsecure zones are
defined as any IP, subnet, or region that is defined as a threat to the
organization. The nonsecure zones must be defined for public web servers
logically located in a DMZ, as well as private web servers with perimeter
protection devices. By restricting access from nonsecure zones, through
internal web server access list, the web server can stop or slow denial of
service (DoS) attacks on the web server.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000315-WSR-000004"
  tag "gid": "V-55961"
  tag "rid": "SV-70215r2_rule"
  tag "stig_id": "SRG-APP-000315-WSR-000004"
  tag "fix_id": "F-60839r1_fix"
  tag "cci": ["CCI-002314"]
  tag "nist": ["AC-17 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server configuration to verify that the web
server is restricting access from nonsecure zones.

If the web server is not configured to restrict access from nonsecure zones,
then this is a finding."
  tag "fix": "Configure the web server to block access from DoD-defined
nonsecure zones."
end

control "V-55969" do
  title "The web server must not impede the ability to write specified log
record content to an audit log server."
  desc  "Writing events to a centralized management audit system offers many
benefits to the enterprise over having dispersed logs. Centralized management
of audit records and logs provides for efficiency in maintenance and management
of records, enterprise analysis of events, and backup and archiving of event
records enterprise-wide. The web server and related components are required to
be capable of writing logs to centralized audit log servers."
  impact 0.5
  tag "gtitle": "SRG-APP-000358-WSR-000063"
  tag "gid": "V-55969"
  tag "rid": "SV-70223r2_rule"
  tag "stig_id": "SRG-APP-000358-WSR-000063"
  tag "fix_id": "F-60847r1_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the web server can write log data to, or if log
data can be transferred to, a separate audit server.

Request a user access the hosted application and generate logable events and
verify the data is written to a separate audit server.

If logs cannot be directly written or transferred on request or on a periodic
schedule to an audit log server, this is a finding."
  tag "fix": "Configure the web server to directly write or transfer the logs
to a remote audit log server."
end

control "V-55971" do
  title "The web server must be configurable to integrate with an organizations
security infrastructure."
  desc  "A web server will typically utilize logging mechanisms for maintaining
a historical log of activity that occurs within a hosted application. This
information can then be used for diagnostic purposes, forensics purposes, or
other purposes relevant to ensuring the availability and integrity of the
hosted application.

    While it is important to log events identified as being critical and
relevant to security, it is equally important to notify the appropriate
personnel in a timely manner so they are able to respond to events as they
occur.

    Manual review of the web server logs may not occur in a timely manner, and
each event logged is open to interpretation by a reviewer. By integrating the
web server into an overall or organization-wide log review, a larger picture of
events can be viewed, and analysis can be done in a timely and reliable manner.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000358-WSR-000163"
  tag "gid": "V-55971"
  tag "rid": "SV-70225r2_rule"
  tag "stig_id": "SRG-APP-000358-WSR-000163"
  tag "fix_id": "F-60849r1_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether the web server is logging security-relevant events.

Determine whether there is a security tool in place that allows review and
alert capabilities and whether the web server is sending events to this system.

If the web server is not, this is a finding."
  tag "fix": "Configure the web server to send logged events to the
organization's security infrastructure tool that offers review and alert
capabilities."
end

control "V-55973" do
  title "The web server must use a logging mechanism that is configured to
alert the ISSO and SA in the event of a processing failure."
  desc  "Reviewing log data allows an investigator to recreate the path of an
attacker and to capture forensic data for later use. Log data is also essential
to system administrators in their daily administrative duties on the hosted
system or within the hosted applications.

    If the logging system begins to fail, events will not be recorded.
Organizations shall define logging failure events, at which time the
application or the logging mechanism the application utilizes will provide a
warning to the ISSO and SA at a minimum.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000108-WSR-000166"
  tag "gid": "V-55973"
  tag "rid": "SV-70227r2_rule"
  tag "stig_id": "SRG-APP-000108-WSR-000166"
  tag "fix_id": "F-60851r2_fix"
  tag "cci": ["CCI-000139"]
  tag "nist": ["AU-5 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration settings to determine if the web server logging system provides
an alert to the ISSO and the SA at a minimum when a processing failure occurs.

If alerts are not sent or the web server is not configured to use a dedicated
logging tool that meets this requirement, this is a finding."
  tag "fix": "Configure the web server to provide an alert to the ISSO and SA
when log processing failures occur.

If the web server cannot generate alerts, utilize an external logging system
that meets this criterion."
end

control "V-55975" do
  title "The web server must use a logging mechanism that is configured to
provide a warning to the ISSO and SA when allocated record storage volume
reaches 75% of maximum log record storage capacity."
  desc  "It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process logs as required. Log processing failures
include: software/hardware errors, failures in the log capturing mechanisms,
and log storage capacity being reached or exceeded.

    If log capacity were to be exceeded, then events subsequently occurring
would not be recorded. Organizations shall define a maximum allowable
percentage of storage capacity serving as an alarming threshold (e.g., web
server has exceeded 75% of log storage capacity allocated), at which time the
web server or the logging mechanism the web server utilizes will provide a
warning to the ISSO and SA at a minimum.

    This requirement can be met by configuring the web server to utilize a
dedicated log tool that meets this requirement.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000359-WSR-000065"
  tag "gid": "V-55975"
  tag "rid": "SV-70229r2_rule"
  tag "stig_id": "SRG-APP-000359-WSR-000065"
  tag "fix_id": "F-60853r1_fix"
  tag "cci": ["CCI-001855"]
  tag "nist": ["AU-5 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration settings to determine if the web server log system provides a
warning to the ISSO and SA when allocated record storage volume reaches 75% of
maximum record storage capacity.

If designated alerts are not sent or the web server is not configured to use a
dedicated log tool that meets this requirement, this is a finding."
  tag "fix": "Configure the web server to provide a warning to the ISSO and SA
when allocated log record storage volume reaches 75% of maximum record storage
capacity."
end

control "V-55977" do
  title "The web server must record time stamps for log records to a minimum
granularity of one second."
  desc  "Without sufficient granularity of time stamps, it is not possible to
adequately determine the chronological order of records.

    Time stamps generated by the web server include date and time and must be
to a granularity of one second.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000375-WSR-000171"
  tag "gid": "V-55977"
  tag "rid": "SV-70231r2_rule"
  tag "stig_id": "SRG-APP-000375-WSR-000171"
  tag "fix_id": "F-60855r1_fix"
  tag "cci": ["CCI-001889"]
  tag "nist": ["AU-8 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if log records are time stamped to a minimum granularity of one
second.

Have a user generate a logable event and review the log data to determine if
the web server is configured correctly.

If the log data does not contain a time stamp to a minimum granularity of one
second, this is a finding."
  tag "fix": "Configure the web server to record log events with a time stamp
to a granularity of one second."
end

control "V-55979" do
  title "The web server must generate log records that can be mapped to
Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT)."
  desc  "If time stamps are not consistently applied and there is no common
time reference, it is difficult to perform forensic analysis across multiple
devices and log records.

    Time stamps generated by the web server include date and time. Time is
commonly expressed in Coordinated Universal Time (UTC), a modern continuation
of Greenwich Mean Time (GMT), or local time with an offset from UTC.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000374-WSR-000172"
  tag "gid": "V-55979"
  tag "rid": "SV-70233r2_rule"
  tag "stig_id": "SRG-APP-000374-WSR-000172"
  tag "fix_id": "F-60857r1_fix"
  tag "cci": ["CCI-001890"]
  tag "nist": ["AU-8 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine the time stamp format for log data.

If the time stamp is not mapped to UTC or GMT time, this is a finding."
  tag "fix": "Configure the web server to store log data time stamps in a
format that is mapped to UTC or GMT time."
end

control "V-55981" do
  title "The web server application, libraries, and configuration files must
only be accessible to privileged users."
  desc  "A web server can be modified through parameter modification, patch
installation, upgrades to the web server or modules, and security parameter
changes. With each of these changes, there is the potential for an adverse
effect such as a DoS, web server instability, or hosted application instability.

    To limit changes to the web server and limit exposure to any adverse
effects from the changes, files such as the web server application files,
libraries, and configuration files must have permissions and ownership set
properly to only allow privileged users access.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000380-WSR-000072"
  tag "gid": "V-55981"
  tag "rid": "SV-70235r2_rule"
  tag "stig_id": "SRG-APP-000380-WSR-000072"
  tag "fix_id": "F-60859r2_fix"
  tag "cci": ["CCI-001813"]
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if the web server provides unique account roles specifically for the
purposes of segmenting the responsibilities for managing the web server.

Log into the hosting server using a web server role with limited permissions
(e.g., Auditor, Developer, etc.) and verify the account is not able to perform
configuration changes that are not related to that role.

If roles are not defined with limited permissions and restrictions, this is a
finding."
  tag "fix": "Define roles and responsibilities to be used when managing the
web server.

Configure the hosting system to utilize specific roles that restrict access
related to web server system and configuration changes."
end

control "V-55983" do
  title "All web server files must be verified for their integrity (e.g.,
checksums and hashes) before becoming part of the production web server."
  desc  "Being able to verify that a patch, upgrade, certificate, etc., being
added to the web server is unchanged from the producer of the file is essential
for file validation and non-repudiation of the information.

    The web server or hosting system must have a mechanism to verify that
files, before installation, are valid.

    Examples of validation methods are sha1 and md5 hashes and checksums.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000131-WSR-000051"
  tag "gid": "V-55983"
  tag "rid": "SV-70237r2_rule"
  tag "stig_id": "SRG-APP-000131-WSR-000051"
  tag "fix_id": "F-60861r1_fix"
  tag "cci": ["CCI-001749"]
  tag "nist": ["CM-5 (3)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine if the web server validates files before the files
are implemented into the running configuration.

If the web server does not meet this requirement and an external facility is
not available for use, this is a finding."
  tag "fix": "Configure the web server to verify object integrity before
becoming part of the production web server or utilize an external tool designed
to meet this requirement."
end

control "V-55985" do
  title "The web server must be configured in accordance with the security
configuration settings based on DoD security configuration or implementation
guidance, including STIGs, NSA configuration guides, CTOs, and DTMs."
  desc  "Configuring the web server to implement organization-wide security
implementation guides and security checklists guarantees compliance with
federal standards and establishes a common security baseline across the DoD
that reflects the most restrictive security posture consistent with operational
requirements.

    Configuration settings are the set of parameters that can be changed that
affect the security posture and/or functionality of the system.
Security-related parameters are those parameters impacting the security state
of the web server, including the parameters required to satisfy other security
control requirements.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000516-WSR-000174"
  tag "gid": "V-55985"
  tag "rid": "SV-70239r2_rule"
  tag "stig_id": "SRG-APP-000516-WSR-000174"
  tag "fix_id": "F-60863r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if web server is configured in accordance with the security
configuration settings based on DoD security configuration or implementation
guidance.

If the web server is not configured according to the guidance, this is a
finding."
  tag "fix": "Configure the web server to be configured according to DoD
security configuration guidance."
end

control "V-55987" do
  title "All accounts installed with the web server software and tools must
have passwords assigned and default passwords changed."
  desc  "During installation of the web server software, accounts are created
for the web server to operate properly. The accounts installed can have either
no password installed or a default password, which will be known and documented
by the vendor and the user community.

    The first things an attacker will try when presented with a login screen
are the default user identifiers with default passwords. Installed applications
may also install accounts with no password, making the login even easier. Once
the web server is installed, the passwords for any created accounts should be
changed and documented. The new passwords must meet the requirements for all
passwords, i.e., upper/lower characters, numbers, special characters, time
until change, reuse policy, etc.

    Service accounts or system accounts that have no login capability do not
need to have passwords set or changed.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000516-WSR-000079"
  tag "gid": "V-55987"
  tag "rid": "SV-70241r2_rule"
  tag "stig_id": "SRG-APP-000516-WSR-000079"
  tag "fix_id": "F-60865r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine what non-service/system accounts were installed by
the web server installation process.

Verify the passwords for these accounts have been set and/or changed from the
default passwords.

If these accounts still have no password or default passwords, this is a
finding."
  tag "fix": "Set passwords for non-service/system accounts containing no
passwords and change the passwords for accounts which still have default
passwords."
end

control "V-55989" do
  title "The web server must not perform user management for hosted
applications."
  desc  "User management and authentication can be an essential part of any
application hosted by the web server. Along with authenticating users, the user
management function must perform several other tasks like password complexity,
locking users after a configurable number of failed logins, and management of
temporary and emergency accounts; and all of this must be done enterprise-wide.

    The web server contains a minimal user management function, but the web
server user management function does not offer enterprise-wide user management,
and user management is not the primary function of the web server. User
management for the hosted applications should be done through a facility that
is built for enterprise-wide user management, like LDAP and Active Directory.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000015"
  tag "gid": "V-55989"
  tag "rid": "SV-70243r2_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000015"
  tag "fix_id": "F-60867r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if the web server is being used as a user management application.

If the web server is being used to perform user management for the hosted
applications, this is a finding."
  tag "fix": "Configure the web server to disable user management
functionality."
end

control "V-55991" do
  title "The web server must prohibit or restrict the use of nonsecure or
unnecessary ports, protocols, modules, and/or services."
  desc  "Web servers provide numerous processes, features, and functionalities
that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or
too unsecure to run on a production system.

    The web server must provide the capability to disable or deactivate
network-related services that are deemed to be non-essential to the server
mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability
assessments.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000383-WSR-000175"
  tag "gid": "V-55991"
  tag "rid": "SV-70245r2_rule"
  tag "stig_id": "SRG-APP-000383-WSR-000175"
  tag "fix_id": "F-60869r1_fix"
  tag "cci": ["CCI-001762"]
  tag "nist": ["CM-7 (1) (b)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine which ports and protocols are enabled.

Verify that the ports and protocols being used are permitted, necessary for the
operation of the web server and the hosted applications and are secure for a
production system.

If any of the ports or protocols are not permitted, are nonsecure or are not
necessary for web server operation, this is a finding."
  tag "fix": "Configure the web server to disable any ports or protocols that
are not permitted, are nonsecure for a production web server or are not
necessary for web server operation."
end

control "V-55993" do
  title "Anonymous user access to the web server application directories must
be prohibited."
  desc  "In order to properly monitor the changes to the web server and the
hosted applications, logging must be enabled. Along with logging being enabled,
each record must properly contain the changes made and the names of those who
made the changes.

    Allowing anonymous users the capability to change the web server or the
hosted application will not generate proper log information that can then be
used for forensic reporting in the case of a security issue. Allowing anonymous
users to make changes will also grant change capabilities to anybody without
forcing a user to authenticate before the changes can be made.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000211-WSR-000031"
  tag "gid": "V-55993"
  tag "rid": "SV-70247r2_rule"
  tag "stig_id": "SRG-APP-000211-WSR-000031"
  tag "fix_id": "F-60871r1_fix"
  tag "cci": ["CCI-001082"]
  tag "nist": ["SC-2", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if anonymous users can make changes to the web server or any
applications hosted by the web server.

If anonymous users can make changes, this is a finding."
  tag "fix": "Configure the web server to not allow anonymous users to change
the web server or any hosted applications."
end

control "V-55995" do
  title "Web server accounts accessing the directory tree, the shell, or other
operating system functions and utilities must only be administrative accounts."
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. Only the
system administrator needs access to all the system's capabilities, while the
web administrator and associated staff require access and control of the web
content and web server configuration files."
  impact 0.5
  tag "gtitle": "SRG-APP-000211-WSR-000030"
  tag "gid": "V-55995"
  tag "rid": "SV-70249r2_rule"
  tag "stig_id": "SRG-APP-000211-WSR-000030"
  tag "fix_id": "F-60873r1_fix"
  tag "cci": ["CCI-001082"]
  tag "nist": ["SC-2", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine what web server accounts are available on the hosting server.

If non-privileged web server accounts are available with access to functions,
directories, or files not needed for the role of the account, this is a
finding."
  tag "fix": "Limit the functions, directories, and files that are accessible
by each account and role to administrative accounts and remove or modify
non-privileged account access."
end

control "V-55997" do
  title "The web server must be tuned to handle the operational requirements of
the hosted application."
  desc  "A Denial of Service (DoS) can occur when the web server is so
overwhelmed that it can no longer respond to additional requests. A web server
not properly tuned may become overwhelmed and cause a DoS condition even with
expected traffic from users. To avoid a DoS, the web server must be tuned to
handle the expected traffic for the hosted applications."
  impact 0.5
  tag "gtitle": "SRG-APP-000435-WSR-000148"
  tag "gid": "V-55997"
  tag "rid": "SV-70251r2_rule"
  tag "stig_id": "SRG-APP-000435-WSR-000148"
  tag "fix_id": "F-60875r2_fix"
  tag "cci": ["CCI-002385"]
  tag "nist": ["SC-5", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine what parameters are set to tune the web server.

Review the hosted applications along with risk analysis documents to determine
the expected user traffic.

If the web server has not been tuned to avoid a DoS, this is a finding."
  tag "fix": "Analyze the expected user traffic for the hosted applications.

Tune the web server to avoid a DoS condition under normal user traffic to the
hosted applications."
end

control "V-55999" do
  title "The web server must be protected from being stopped by a
non-privileged user."
  desc  "An attacker has at least two reasons to stop a web server. The first
is to cause a DoS, and the second is to put in place changes the attacker made
to the web server configuration.

    To prohibit an attacker from stopping the web server, the process ID (pid)
of the web server and the utilities used to start/stop the web server must be
protected from access by non-privileged users. By knowing the pid and having
access to the web server utilities, a non-privileged user has a greater
capability of stopping the server, whether intentionally or unintentionally.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000435-WSR-000147"
  tag "gid": "V-55999"
  tag "rid": "SV-70253r2_rule"
  tag "stig_id": "SRG-APP-000435-WSR-000147"
  tag "fix_id": "F-60877r1_fix"
  tag "cci": ["CCI-002385"]
  tag "nist": ["SC-5", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine where the process ID is stored and which utilities are used to
start/stop the web server.

Determine whether the process ID and the utilities are protected from
non-privileged users.

If they are not protected, this is a finding."
  tag "fix": "Remove or modify non-privileged account access to the web server
process ID and the utilities used for starting/stopping the web server."
end

control "V-56001" do
  title "The web server must employ cryptographic mechanisms (TLS/DTLS/SSL)
preventing the unauthorized disclosure of information during transmission."
  desc  "Preventing the disclosure of transmitted information requires that the
web server take measures to employ some form of cryptographic mechanism in
order to protect the information during transmission. This is usually achieved
through the use of Transport Layer Security (TLS).

    Transmission of data can take place between the web server and a large
number of devices/applications external to the web server. Examples are a web
client used by a user, a backend database, an audit server, or other web
servers in a web cluster.

    If data is transmitted unencrypted, the data then becomes vulnerable to
disclosure. The disclosure may reveal user identifier/password combinations,
website code revealing business logic, or other user personal information.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000439-WSR-000151"
  tag "gid": "V-56001"
  tag "rid": "SV-70255r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000151"
  tag "fix_id": "F-60879r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether the transmission of data between the web server and
external devices is encrypted.

If the web server does not encrypt the transmission, this is a finding."
  tag "fix": "Configure the web server to encrypt the transmission of data
between the web server and external devices."
end

control "V-56003" do
  title "Web server session IDs must be sent to the client using SSL/TLS."
  desc  "The HTTP protocol is a stateless protocol. To maintain a session, a
session identifier is used. The session identifier is a piece of data that is
used to identify a session and a user. If the session identifier is compromised
by an attacker, the session can be hijacked. By encrypting the session
identifier, the identifier becomes more difficult for an attacker to hijack,
decrypt, and use before the session has expired."
  impact 0.5
  tag "gtitle": "SRG-APP-000439-WSR-000152"
  tag "gid": "V-56003"
  tag "rid": "SV-70257r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000152"
  tag "fix_id": "F-60881r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether the session identifier is being sent to the client
encrypted.

If the web server does not encrypt the session identifier, this is a finding."
  tag "fix": "Configure the web server to encrypt the session identifier for
transmission to the client."
end

control "V-56005" do
  title "Web server cookies, such as session cookies, sent to the client using
SSL/TLS must not be compressed."
  desc  "A cookie is used when a web server needs to share data with the
client's browser. The data is often used to remember the client when the client
returns to the hosted application at a later date. A session cookie is a
special type of cookie used to remember the client during the session. The
cookie will contain the session identifier (ID) and may contain authentication
data to the hosted application. To protect this data from easily being
compromised, the cookie can be encrypted.

    When a cookie is sent encrypted via SSL/TLS, an attacker must spend a great
deal of time and resources to decrypt the cookie. If, along with encryption,
the cookie is compressed, the attacker can now use a combination of plaintext
injection and inadvertent information leakage through data compression to
reduce the time needed to decrypt the cookie. This attack is called Compression
Ratio Info-leak Made Easy (CRIME).

    Cookies shared between the web server and the client when encrypted should
not also be compressed.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000439-WSR-000153"
  tag "gid": "V-56005"
  tag "rid": "SV-70259r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000153"
  tag "fix_id": "F-60883r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether cookies are being sent to the client using SSL/TLS.

If the transmission is through a SSL/TLS connection, but the cookie is not
being compressed, this finding is NA.

If the web server is using SSL/TLS for cookie transmission and the cookie is
also being compressed, this is a finding."
  tag "fix": "Configure the web server to send the cookie to the client via
SSL/TLS without using cookie compression."
end

control "V-56007" do
  title "Cookies exchanged between the web server and the client, such as
session cookies, must have cookie properties set to prohibit client-side
scripts from reading the cookie data."
  desc  "A cookie can be read by client-side scripts easily if cookie
properties are not set properly. By allowing cookies to be read by the
client-side scripts, information such as session identifiers could be
compromised and used by an attacker who intercepts the cookie. Setting cookie
properties (i.e. HttpOnly property) to disallow client-side scripts from
reading cookies better protects the information inside the cookie."
  impact 0.5
  tag "gtitle": "SRG-APP-000439-WSR-000154"
  tag "gid": "V-56007"
  tag "rid": "SV-70261r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000154"
  tag "fix_id": "F-60885r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine how to disable client-side scripts from reading cookies.

If the web server is not configured to disallow client-side scripts from
reading cookies, this is a finding."
  tag "fix": "Configure the web server to disallow client-side scripts the
capability of reading cookie information."
end

control "V-56009" do
  title "Cookies exchanged between the web server and the client, such as
session cookies, must have cookie properties set to force the encryption of
cookies."
  desc  "Cookies can be sent to a client using TLS/SSL to encrypt the cookies,
but TLS/SSL is not used by every hosted application since the data being
displayed does not require the encryption of the transmission. To safeguard
against cookies, especially session cookies, being sent in plaintext, a cookie
can be encrypted before transmission. To force a cookie to be encrypted before
transmission, the cookie Secure property can be set."
  impact 0.5
  tag "gtitle": "SRG-APP-000439-WSR-000155"
  tag "gid": "V-56009"
  tag "rid": "SV-70263r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000155"
  tag "fix_id": "F-60887r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to verify that cookies are encrypted before transmission.

If the web server is not configured to encrypt cookies, this is a finding."
  tag "fix": "Configure the web server to encrypt cookies before transmission."
end

control "V-56011" do
  title "A web server must maintain the confidentiality of controlled
information during transmission through the use of an approved TLS version."
  desc  "Transport Layer Security (TLS) is a required transmission protocol for
a web server hosting controlled information. The use of TLS provides
confidentiality of data in transit between the web server and client. FIPS
140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions
must be disabled.

    NIST SP 800-52 defines the approved TLS versions for government
applications.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000439-WSR-000156"
  tag "gid": "V-56011"
  tag "rid": "SV-70265r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000156"
  tag "fix_id": "F-60889r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine which version of TLS is being used.

If the TLS version is not an approved version according to NIST SP 800-52 or
non-FIPS-approved algorithms are enabled, this is a finding."
  tag "fix": "Configure the web server to use an approved TLS version according
to NIST SP 800-52 and to disable all non-approved versions."
end

control "V-56013" do
  title "The web server must maintain the confidentiality and integrity of
information during preparation for transmission."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during preparation for transmission, including, for example, during
aggregation, at protocol transformation points, and during packing/unpacking.
These unauthorized disclosures or modifications compromise the confidentiality
or integrity of the information.

    An example of this would be an SMTP queue. This queue may be added to a web
server through an SMTP module to enhance error reporting or to allow developers
to add SMTP functionality to their applications.

    Any modules used by the web server that queue data before transmission must
maintain the confidentiality and integrity of the information before the data
is transmitted.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000441-WSR-000181"
  tag "gid": "V-56013"
  tag "rid": "SV-70267r2_rule"
  tag "stig_id": "SRG-APP-000441-WSR-000181"
  tag "fix_id": "F-60891r1_fix"
  tag "cci": ["CCI-002420"]
  tag "nist": ["SC-8 (2)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if the web server maintains the confidentiality and integrity of
information during preparation before transmission.

If the confidentiality and integrity are not maintained, this is a finding."
  tag "fix": "Configure the web server to maintain the confidentiality and
integrity of information during preparation for transmission."
end

control "V-56015" do
  title "The web server must maintain the confidentiality and integrity of
information during reception."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during reception, including, for example, during aggregation, at
protocol transformation points, and during packing/unpacking. These
unauthorized disclosures or modifications compromise the confidentiality or
integrity of the information.

    Protecting the confidentiality and integrity of received information
requires that application servers take measures to employ approved cryptography
in order to protect the information during transmission over the network. This
is usually achieved through the use of Transport Layer Security (TLS), SSL VPN,
or IPsec tunnel.

    The web server must utilize approved encryption when receiving transmitted
data.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000442-WSR-000182  "
  tag "gid": "V-56015"
  tag "rid": "SV-70269r2_rule"
  tag "stig_id": "SRG-APP-000442-WSR-000182"
  tag "fix_id": "F-60893r1_fix"
  tag "cci": ["CCI-002422"]
  tag "nist": ["SC-8 (2)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review web server configuration to determine if the server is
using a transmission method that maintains the confidentiality and integrity of
information during reception.

If a transmission method is not being used that maintains the confidentiality
and integrity of the data during reception, this is a finding."
  tag "fix": "Configure the web server to utilize a transmission method that
maintains the confidentiality and integrity of information during reception."
end

control "V-56017" do
  title "The web server must implement required cryptographic protections using
cryptographic modules complying with applicable federal laws, Executive Orders,
directives, policies, regulations, standards, and guidance when encrypting data
that must be compartmentalized."
  desc  "Cryptography is only as strong as the encryption modules/algorithms
employed to encrypt the data.

    Use of weak or untested encryption algorithms undermines the purposes of
utilizing encryption to protect data.

    NSA has developed Type 1 algorithms for protecting classified information.
The Committee on National Security Systems (CNSS) National Information
Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:

    \"Cryptographic equipment, assembly or component classified or certified by
NSA for encrypting and decrypting classified and sensitive national security
information when appropriately keyed. Developed using established NSA business
processes and containing NSA-approved algorithms are used to protect systems
requiring the most stringent protection mechanisms.\"

    Although persons may have a security clearance, they may not have a
\"need-to-know\" and are required to be separated from the information in
question. The web server must employ NSA-approved cryptography to protect
classified information from those individuals who have no \"need-to-know\" or
when encryption of compartmentalized data is required by data classification.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000416-WSR-000118"
  tag "gid": "V-56017"
  tag "rid": "SV-70271r2_rule"
  tag "stig_id": "SRG-APP-000416-WSR-000118"
  tag "fix_id": "F-60895r1_fix"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review policy documents to identify data that is
compartmentalized (i.e. classified, sensitive, need-to-know, etc.) and requires
cryptographic protection.

Review the web server documentation and deployed configuration to identify the
encryption modules utilized to protect the compartmentalized data.

If the encryption modules used to protect the compartmentalized data are not
compliant with the data, this is a finding."
  tag "fix": "Configure the web server to utilize cryptography when protecting
compartmentalized data."
end

control "V-56019" do
  title "A web server utilizing mobile code must meet DoD-defined mobile code
requirements."
  desc  "Mobile code in hosted applications allows the developer to add
functionality and displays to hosted applications that are fluid, as opposed to
a static web page. The data presentation becomes more appealing to the user, is
easier to analyze, and navigation through the hosted application and data is
much less complicated.

    Some mobile code technologies in use in today's applications are: Java,
JavaScript, ActiveX, PDF, Postscript, Shockwave movies, Flash animations, and
VBScript. The DoD has created policies that define the usage of mobile code on
DoD systems. The usage restrictions and implementation guidance apply to both
the selection and use of mobile code installed on organizational servers and
mobile code downloaded and executed on individual workstations.

    The web server may host applications that contain mobile code and
therefore, must meet the DoD-defined requirements regarding the deployment
and/or use of mobile code. This includes digitally signing applets in order to
provide a means for the client to establish application authenticity.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000206-WSR-000128"
  tag "gid": "V-56019"
  tag "rid": "SV-70273r2_rule"
  tag "stig_id": "SRG-APP-000206-WSR-000128"
  tag "fix_id": "F-60897r1_fix"
  tag "cci": ["CCI-001166"]
  tag "nist": ["SC-18 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether mobile code used by hosted applications follows the DoD
policies on the acquisition, development, and/or use of mobile code.

If the web server is not configured to follow the DoD policies on mobile code,
this is a finding."
  tag "fix": "Configure the web server to follow the DoD policies on mobile
code."
end

control "V-56021" do
  title "The web server must invalidate session identifiers upon hosted
application user logout or other session termination."
  desc  "Captured sessions can be reused in \"replay\" attacks. This
requirement limits the ability of adversaries from capturing and continuing to
employ previously valid session IDs.

    Session IDs are tokens generated by web applications to uniquely identify
an application user's session. Unique session IDs help to reduce predictability
of said identifiers. When a user logs out, or when any other session
termination event occurs, the web server must terminate the user session to
minimize the potential for an attacker to hijack that particular user session.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000220-WSR-000201"
  tag "gid": "V-56021"
  tag "rid": "SV-70275r2_rule"
  tag "stig_id": "SRG-APP-000220-WSR-000201"
  tag "fix_id": "F-60899r1_fix"
  tag "cci": ["CCI-001185"]
  tag "nist": ["SC-23 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to verify that the web server is configured to invalidate session identifiers
when a session is terminated.

If the web server does not invalidate session identifiers when a session is
terminated, this is a finding."
  tag "fix": "Configure the web server to invalidate session identifiers when a
session is terminated."
end

control "V-56023" do
  title "The web server must generate a unique session identifier for each
session using a FIPS 140-2 approved random number generator."
  desc  "Communication between a client and the web server is done using the
HTTP protocol, but HTTP is a stateless protocol. In order to maintain a
connection or session, a web server will generate a session identifier (ID) for
each client session when the session is initiated. The session ID allows the
web server to track a user session and, in many cases, the user, if the user
previously logged into a hosted application.

    Unique session IDs are the opposite of sequentially generated session IDs,
which can be easily guessed by an attacker. Unique session identifiers help to
reduce predictability of generated identifiers. Unique session IDs address
man-in-the-middle attacks, including session hijacking or insertion of false
information into a session. If the attacker is unable to identify or guess the
session information related to pending application traffic, the attacker will
have more difficulty in hijacking the session or otherwise manipulating valid
sessions.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000224-WSR-000135"
  tag "gid": "V-56023"
  tag "rid": "SV-70277r2_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000135"
  tag "fix_id": "F-60901r1_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to verify that the web server is configured to generate unique session
identifiers with a FIPS 140-2 approved random number generator.

Request two users access the web server and view the session identifier
generated for each user to verify that the session IDs are not sequential.

If the web server is not configured to generate unique session identifiers or
the random number generator is not FIPS 140-2 approved, this is a finding."
  tag "fix": "Configure the web server to generate unique session identifiers
using a FIPS 140-2 random number generator."
end

control "V-56025" do
  title "Cookies exchanged between the web server and client, such as session
cookies, must have security settings that disallow cookie access outside the
originating web server and hosted application."
  desc  "Cookies are used to exchange data between the web server and the
client. Cookies, such as a session cookie, may contain session information and
user credentials used to maintain a persistent connection between the user and
the hosted application since HTTP/HTTPS is a stateless protocol.

    When the cookie parameters are not set properly (i.e., domain and path
parameters), cookies can be shared within hosted applications residing on the
same web server or to applications hosted on different web servers residing on
the same domain.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000223-WSR-000011"
  tag "gid": "V-56025"
  tag "rid": "SV-70279r2_rule"
  tag "stig_id": "SRG-APP-000223-WSR-000011"
  tag "fix_id": "F-60903r1_fix"
  tag "cci": ["CCI-001664"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if cookies between the web server and client are accessible by
applications or web servers other than the originating pair.

If the cookie information is accessible outside the originating pair, this is a
finding."
  tag "fix": "Configure the web server to set properties within cookies to
disallow the cookie to be accessed by other web servers and applications."
end

control "V-56027" do
  title "The web server must only accept client certificates issued by DoD PKI
or DoD-approved PKI Certification Authorities (CAs)."
  desc  "Non-DoD approved PKIs have not been evaluated to ensure that they have
security controls and identity vetting procedures in place which are sufficient
for DoD systems to rely on the identity asserted in the certificate. PKIs
lacking sufficient security controls and identity vetting procedures risk being
compromised and issuing certificates that enable adversaries to impersonate
legitimate users."
  impact 0.5
  tag "gtitle": "SRG-APP-000427-WSR-000186"
  tag "gid": "V-56027"
  tag "rid": "SV-70281r2_rule"
  tag "stig_id": "SRG-APP-000427-WSR-000186"
  tag "fix_id": "F-60905r1_fix"
  tag "cci": ["CCI-002470"]
  tag "nist": ["SC-23 (5)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server deployed configuration to determine if
the web server will accept client certificates issued by unapproved PKIs. The
authoritative list of DoD-approved PKIs is published at
http://iase.disa.mil/pki-pke/interoperability.

If the web server will accept non-DoD approved PKI client certificates, this is
a finding."
  tag "fix": "Configure the web server to only accept DoD and DoD-approved PKI
client certificates."
end

control "V-56029" do
  title "The web server must augment re-creation to a stable and known
baseline."
  desc  "Making certain that the web server has not been updated by an
unauthorized user is always a concern. Adding patches, functions, and modules
that are untested and not part of the baseline opens the possibility for
security risks. The web server must offer, and not hinder, a method that allows
for the quick and easy reinstallation of a verified and patched baseline to
guarantee the production web server is up-to-date and has not been modified to
add functionality or expose security risks.

    When the web server does not offer a method to roll back to a clean
baseline, external methods, such as a baseline snapshot or virtualizing the web
server, can be used.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000225-WSR-000074"
  tag "gid": "V-56029"
  tag "rid": "SV-70283r2_rule"
  tag "stig_id": "SRG-APP-000225-WSR-000074"
  tag "fix_id": "F-60907r1_fix"
  tag "cci": ["CCI-001190"]
  tag "nist": ["SC-24", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if the web server offers the capability to reinstall from a known
state.

If the web server does not offer this capability, determine if the web server,
in any manner, prohibits the reinstallation of a known state.

If the web server does prohibit the reinstallation to a known state, this is a
finding."
  tag "fix": "Configure the web server to augment and not hinder the
reinstallation of a known and stable baseline."
end

control "V-56031" do
  title "The web server must encrypt user identifiers and passwords."
  desc  "When data is written to digital media, such as hard drives, mobile
computers, external/removable hard drives, personal digital assistants,
flash/thumb drives, etc., there is risk of data loss and data compromise. User
identities and passwords stored on the hard drive of the hosting hardware must
be encrypted to protect the data from easily being discovered and used by an
unauthorized user to access the hosted applications. The cryptographic
libraries and functionality used to store and retrieve the user identifiers and
passwords must be part of the web server."
  impact 0.5
  tag "gtitle": "SRG-APP-000429-WSR-000113"
  tag "gid": "V-56031"
  tag "rid": "SV-70285r2_rule"
  tag "stig_id": "SRG-APP-000429-WSR-000113"
  tag "fix_id": "F-60909r1_fix"
  tag "cci": ["CCI-002476"]
  tag "nist": ["SC-28 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine whether the web server is authorizing and managing users.

If the web server is not authorizing and managing users, this is NA.

If the web server is the user authenticator and manager, verify that stored
user identifiers and passwords are being encrypted by the web server. If the
user information is not being encrypted when stored, this is a finding."
  tag "fix": "Configure the web server to encrypt the user identifiers and
passwords when storing them on digital media."
end

control "V-56033" do
  title "The web server must install security-relevant software updates within
the configured time period directed by an authoritative source (e.g. IAVM,
CTOs, DTMs, and STIGs)."
  desc  "Security flaws with software applications are discovered daily.
Vendors are constantly updating and patching their products to address newly
discovered security vulnerabilities. Organizations (including any contractor to
the organization) are required to promptly install security-relevant software
updates (e.g., patches, service packs, and hot fixes). Flaws discovered during
security assessments, continuous monitoring, incident response activities, or
information system error handling must also be addressed expeditiously.

    The web server will be configured to check for and install
security-relevant software updates from an authoritative source within an
identified time period from the availability of the update. By default, this
time period will be every 24 hours.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000456-WSR-000187"
  tag "gid": "V-56033"
  tag "rid": "SV-70287r2_rule"
  tag "stig_id": "SRG-APP-000456-WSR-000187"
  tag "fix_id": "F-60911r1_fix"
  tag "cci": ["CCI-002605"]
  tag "nist": ["SI-2 c", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if the web server checks for patches from an authoritative source at
least every 24 hours.

If there is no timeframe or the timeframe is greater than 24 hours, this is a
finding."
  tag "fix": "Configure the web server to check for patches and updates from an
authoritative source at least every 24 hours."
end

control "V-56035" do
  title "The web server must display a default hosted application web page, not
a directory listing, when a requested web page cannot be found."
  desc  "The goal is to completely control the web user's experience in
navigating any portion of the web document root directories. Ensuring all web
content directories have at least the equivalent of an index.html file is a
significant factor to accomplish this end.

    Enumeration techniques, such as URL parameter manipulation, rely upon being
able to obtain information about the web server's directory structure by
locating directories without default pages. In the scenario, the web server
will display to the user a listing of the files in the directory being
accessed. By having a default hosted application web page, the anonymous web
user will not obtain directory browsing information or an error message that
reveals the server type and version.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000266-WSR-000142"
  tag "gid": "V-56035"
  tag "rid": "SV-70289r2_rule"
  tag "stig_id": "SRG-APP-000266-WSR-000142"
  tag "fix_id": "F-60913r1_fix"
  tag "cci": ["CCI-001312"]
  tag "nist": ["SI-11 a", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to locate all the web document directories.

Verify that each web document directory contains a default hosted application
web page that can be used by the web server in the event a web page cannot be
found.

If a document directory does not contain a default web page, this is a finding."
  tag "fix": "Place a default web page in every web document directory."
end

control "V-61353" do
  title "The web server must remove all export ciphers to protect the
confidentiality and integrity of transmitted information."
  desc  "During the initial setup of a Transport Layer Security (TLS)
connection to the web server, the client sends a list of supported cipher
suites in order of preference.  The web server will reply with the cipher suite
it will use for communication from the client list.  If an attacker can
intercept the submission of cipher suites to the web server and place, as the
preferred cipher suite, a weak export suite, the encryption used for the
session becomes easy for the attacker to break, often within minutes to hours."
  impact 0.5
  tag "gtitle": "SRG-APP-000439-WSR-000188 "
  tag "gid": "V-61353"
  tag "rid": "SV-75835r1_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000188"
  tag "fix_id": "F-67255r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine if export ciphers are removed.

If the web server does not have the export ciphers removed, this is a finding.
"
  tag "fix": "Configure the web server to have export ciphers removed."
end

