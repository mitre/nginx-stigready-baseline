control "V-41730" do
  title "The web server must perform RFC 5280-compliant certification path
validation."
  desc  "A certificate's certification path is the path from the end entity
certificate to a trusted root certification authority (CA). Certification path
validation is necessary for a relying party to make an informed decision
regarding acceptance of an end entity certificate. Certification path
validation includes checks such as certificate issuer trust, time validity and
revocation status for each certificate in the certification path. Revocation
status information for CA and subject certificates in a certification path is
commonly provided via certificate revocation lists (CRLs) or online certificate
status protocol (OCSP) responses."
  impact 0.5
  tag "gtitle": "SRG-APP-000175-WSR-000095"
  tag "gid": "V-41730"
  tag "rid": "SV-54307r3_rule"
  tag "stig_id": "SRG-APP-000175-WSR-000095"
  tag "fix_id": "F-47189r4_fix"
  tag "cci": ["CCI-000185"]
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]
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
to determine whether the web server provides PKI functionality that validates
certification paths in accordance with RFC 5280. If PKI is not being used, this
is NA.

If the web server is using PKI, but it does not perform this requirement, this
is a finding."
  tag "fix": "Configure the web server to validate certificates in accordance
with RFC 5280."
end

