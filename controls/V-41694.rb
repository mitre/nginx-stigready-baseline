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

