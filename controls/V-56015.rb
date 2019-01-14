control "V-56015" do
  title "The web server must maintain the confidentiality and integrity of
information during reception."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during reception, including, for example, during aggregation, at
protocol transformation points, and during packing/unpacking. These
unauthorized disclosures or modifications compromise the confidentiality or
integrity of the information.

    Protecting the confidentiality and integrity of received information
requires that application servers take measures to employ approved cryptography
in order to protect the information during transmission over the network. This
is usually achieved through the use of Transport Layer Security (TLS), SSL VPN,
or IPsec tunnel.

    The web server must utilize approved encryption when receiving transmitted
data.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000442-WSR-000182  "
  tag "gid": "V-56015"
  tag "rid": "SV-70269r2_rule"
  tag "stig_id": "SRG-APP-000442-WSR-000182"
  tag "fix_id": "F-60893r1_fix"
  tag "cci": ["CCI-002422"]
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
  tag "check": "Review web server configuration to determine if the server is
using a transmission method that maintains the confidentiality and integrity of
information during reception.

If a transmission method is not being used that maintains the confidentiality
and integrity of the data during reception, this is a finding."
  tag "fix": "Configure the web server to utilize a transmission method that
maintains the confidentiality and integrity of information during reception."
end

