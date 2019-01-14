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

