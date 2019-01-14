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

