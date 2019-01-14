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

