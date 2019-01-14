control "V-56013" do
  title "The web server must maintain the confidentiality and integrity of
information during preparation for transmission."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during preparation for transmission, including, for example, during
aggregation, at protocol transformation points, and during packing/unpacking.
These unauthorized disclosures or modifications compromise the confidentiality
or integrity of the information.

    An example of this would be an SMTP queue. This queue may be added to a web
server through an SMTP module to enhance error reporting or to allow developers
to add SMTP functionality to their applications.

    Any modules used by the web server that queue data before transmission must
maintain the confidentiality and integrity of the information before the data
is transmitted.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000441-WSR-000181"
  tag "gid": "V-56013"
  tag "rid": "SV-70267r2_rule"
  tag "stig_id": "SRG-APP-000441-WSR-000181"
  tag "fix_id": "F-60891r1_fix"
  tag "cci": ["CCI-002420"]
  tag "nist": ["SC-8 (2)", "Rev_4"]
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
to determine if the web server maintains the confidentiality and integrity of
information during preparation before transmission.

If the confidentiality and integrity are not maintained, this is a finding."
  tag "fix": "Configure the web server to maintain the confidentiality and
integrity of information during preparation for transmission."
end

