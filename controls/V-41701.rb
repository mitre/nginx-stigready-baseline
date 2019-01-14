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

