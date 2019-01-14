control "V-41615" do
  title "The web server must produce log records containing sufficient
information to establish the source of events."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct source, e.g. source IP, of the events is important
during forensic analysis. Correctly determining the source will add information
to the overall reconstruction of the logable event. By determining the source
of the event correctly, analysis of the enterprise can be undertaken to
determine if the event compromised other assets within the enterprise.

    Without sufficient information establishing the source of the logged event,
investigation into the cause of event is severely hindered. Log record content
that may be necessary to satisfy the requirement of this control includes, but
is not limited to, time stamps, source and destination IP addresses,
user/process identifiers, event descriptions, application-specific events,
success/fail indications, file names involved, access control, or flow control
rules invoked.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000098-WSR-000059"
  tag "gid": "V-41615"
  tag "rid": "SV-54192r3_rule"
  tag "stig_id": "SRG-APP-000098-WSR-000059"
  tag "fix_id": "F-47074r2_fix"
  tag "cci": ["CCI-000133"]
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
configuration to determine if the web server is configured to generate
sufficient information to resolve the source, e.g. source IP, of the log event.

Request a user access the hosted application and generate logable events, and
then review the logs to determine if the source of the event can be established.

If the source of the event cannot be determined, this is a finding."
  tag "fix": "Configure the web server to generate the source of each logable
event."
end

