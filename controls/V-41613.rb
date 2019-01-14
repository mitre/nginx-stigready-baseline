control "V-41613" do
  title "The web server must produce log records containing sufficient
information to establish when (date and time) events occurred."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct order of the events that occurred is important
during forensic analysis. Events that appear harmless by themselves might be
flagged as a potential threat when properly viewed in sequence. By also
establishing the event date and time, an event can be properly viewed with an
enterprise tool to fully see a possible threat in its entirety.

    Without sufficient information establishing when the log event occurred,
investigation into the cause of event is severely hindered. Log record content
that may be necessary to satisfy the requirement of this control includes, but
is not limited to, time stamps, source and destination IP addresses,
user/process identifiers, event descriptions, application-specific events,
success/fail indications, file names involved, access control, or flow control
rules invoked.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000096-WSR-000057"
  tag "gid": "V-41613"
  tag "rid": "SV-54190r3_rule"
  tag "stig_id": "SRG-APP-000096-WSR-000057"
  tag "fix_id": "F-47072r2_fix"
  tag "cci": ["CCI-000131"]
  tag "nist": ["AU-3", "Rev_4"]
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
configuration to determine if the web server is configured to generate a date
and time for each logged event.

Request a user access the hosted application and generate logable events, and
then review the logs to determine if the date and time are included in the log
event data.

If the date and time are not included, this is a finding."
  tag "fix": "Configure the web server to log date and time with the event."
end

