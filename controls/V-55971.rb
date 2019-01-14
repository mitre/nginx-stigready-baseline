control "V-55971" do
  title "The web server must be configurable to integrate with an organizations
security infrastructure."
  desc  "A web server will typically utilize logging mechanisms for maintaining
a historical log of activity that occurs within a hosted application. This
information can then be used for diagnostic purposes, forensics purposes, or
other purposes relevant to ensuring the availability and integrity of the
hosted application.

    While it is important to log events identified as being critical and
relevant to security, it is equally important to notify the appropriate
personnel in a timely manner so they are able to respond to events as they
occur.

    Manual review of the web server logs may not occur in a timely manner, and
each event logged is open to interpretation by a reviewer. By integrating the
web server into an overall or organization-wide log review, a larger picture of
events can be viewed, and analysis can be done in a timely and reliable manner.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000358-WSR-000163"
  tag "gid": "V-55971"
  tag "rid": "SV-70225r2_rule"
  tag "stig_id": "SRG-APP-000358-WSR-000163"
  tag "fix_id": "F-60849r1_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]
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
to determine whether the web server is logging security-relevant events.

Determine whether there is a security tool in place that allows review and
alert capabilities and whether the web server is sending events to this system.

If the web server is not, this is a finding."
  tag "fix": "Configure the web server to send logged events to the
organization's security infrastructure tool that offers review and alert
capabilities."
end

