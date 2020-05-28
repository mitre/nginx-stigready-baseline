# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

DOD_APPROVED_PKIS= input(
  'dod_approved_pkis',
  description: 'DoD-approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners).',
  value: ['DoD',
            'ECA']
)

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
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
whether the web server provides PKI functionality that validates certification
paths in accordance with RFC 5280. If PKI is not being used, this is NA.

    If the web server is using PKI, but it does not perform this requirement,
this is a finding.
  "
  desc  "fix", "Configure the web server to validate certificates in accordance
with RFC 5280."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000175-WSR-000095"
  tag "gid": "V-41730"
  tag "rid": "SV-54307r3_rule"
  tag "stig_id": "SRG-APP-000175-WSR-000095"
  tag "fix_id": "F-47189r4_fix"
  tag "cci": ["CCI-000185"]
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]

  # find / -name ssl.conf  note the path of the file.
  # grep ""ssl_client_certificate"" in conf files in context http,server
  # Review the results to determine the path of the ssl_client_certificate.
  # more /path/of/ca-bundle.crt
  # Examine the contents of this file to determine if the trusted CAs are DoD
  # approved. If the trusted CA that is used to authenticate users to the web site
  # does not lead to an approved DoD CA, this is a finding.
  # NOTE: There are non DoD roots that must be on the server in order for it to
  # function. Some applications, such as anti-virus programs, require root CAs to
  # function. DoD approved certificate can include the External Certificate
  # Authorities (ECA), if approved by the DAA. The PKE InstallRoot 3.06 System
  # Administrator Guide (SAG), dated 8 Jul 2008, contains a complete list of DoD,
  # ECA, and IECA CAs.


  nginx_conf_handle = nginx_conf(conf_path)

  nginx_conf_handle.http.entries.each do |http|
    describe http.params['ssl_client_certificate'] do
      it { should_not be_nil}
    end
    http.params['ssl_client_certificate'].each do |cert|
      describe x509_certificate(cert.join) do
        it { should_not be_nil}
        its('subject.C') { should cmp 'US'}
        its('subject.O') { should cmp 'U.S. Government'}
      end
      describe x509_certificate(cert.join).subject.CN[0..2] do
        it { should be_in DOD_APPROVED_PKIS}
      end
    end unless http.params['ssl_client_certificate'].nil?
  end

  nginx_conf_handle.servers.entries.each do |server|
    server.params['ssl_client_certificate'].each do |cert|
      describe x509_certificate(cert.join) do
        it { should_not be_nil}
        its('subject.C') { should cmp 'US'}
        its('subject.O') { should cmp 'U.S. Government'}
      end
      describe x509_certificate(cert.join).subject.CN[0..2] do
        it { should be_in DOD_APPROVED_PKIS}
      end
    end unless server.params['ssl_client_certificate'].nil?
  end
  
end

