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

