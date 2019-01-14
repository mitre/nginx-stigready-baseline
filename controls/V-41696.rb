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

