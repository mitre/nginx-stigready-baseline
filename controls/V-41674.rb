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

