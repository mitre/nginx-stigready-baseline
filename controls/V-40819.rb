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

