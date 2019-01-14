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

