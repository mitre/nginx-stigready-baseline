control "V-56017" do
  title "The web server must implement required cryptographic protections using
cryptographic modules complying with applicable federal laws, Executive Orders,
directives, policies, regulations, standards, and guidance when encrypting data
that must be compartmentalized."
  desc  "Cryptography is only as strong as the encryption modules/algorithms
employed to encrypt the data.

    Use of weak or untested encryption algorithms undermines the purposes of
utilizing encryption to protect data.

    NSA has developed Type 1 algorithms for protecting classified information.
The Committee on National Security Systems (CNSS) National Information
Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:

    \"Cryptographic equipment, assembly or component classified or certified by
NSA for encrypting and decrypting classified and sensitive national security
information when appropriately keyed. Developed using established NSA business
processes and containing NSA-approved algorithms are used to protect systems
requiring the most stringent protection mechanisms.\"

    Although persons may have a security clearance, they may not have a
\"need-to-know\" and are required to be separated from the information in
question. The web server must employ NSA-approved cryptography to protect
classified information from those individuals who have no \"need-to-know\" or
when encryption of compartmentalized data is required by data classification.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000416-WSR-000118"
  tag "gid": "V-56017"
  tag "rid": "SV-70271r2_rule"
  tag "stig_id": "SRG-APP-000416-WSR-000118"
  tag "fix_id": "F-60895r1_fix"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]
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
  tag "check": "Review policy documents to identify data that is
compartmentalized (i.e. classified, sensitive, need-to-know, etc.) and requires
cryptographic protection.

Review the web server documentation and deployed configuration to identify the
encryption modules utilized to protect the compartmentalized data.

If the encryption modules used to protect the compartmentalized data are not
compliant with the data, this is a finding."
  tag "fix": "Configure the web server to utilize cryptography when protecting
compartmentalized data."
end

