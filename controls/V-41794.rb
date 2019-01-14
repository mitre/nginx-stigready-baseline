control "V-41794" do
  title "The web server must separate the hosted applications from hosted web
server management functionality."
  desc  "The separation of user functionality from web server management can be
accomplished by moving management functions to a separate IP address or port.
To further separate the management functions, separate authentication methods
and certificates should be used.

    By moving the management functionality, the possibility of accidental
discovery of the management functions by non-privileged users during hosted
application use is minimized.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000211-WSR-000129"
  tag "gid": "V-41794"
  tag "rid": "SV-54371r3_rule"
  tag "stig_id": "SRG-APP-000211-WSR-000129"
  tag "fix_id": "F-47253r2_fix"
  tag "cci": ["CCI-001082"]
  tag "nist": ["SC-2", "Rev_4"]
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
to determine whether hosted application functionality is separated from web
server management functions.

If the functions are not separated, this is a finding."
  tag "fix": "Configure the web server to separate the hosted applications from
web server management functionality."
end

