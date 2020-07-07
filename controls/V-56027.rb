# encoding: UTF-8

dod_approved_pkis = input('dod_approved_pkis')

control "V-56027" do
  title "The web server must only accept client certificates issued by DoD PKI
or DoD-approved PKI Certification Authorities (CAs)."
  desc  "Non-DoD approved PKIs have not been evaluated to ensure that they have
security controls and identity vetting procedures in place which are sufficient
for DoD systems to rely on the identity asserted in the certificate. PKIs
lacking sufficient security controls and identity vetting procedures risk being
compromised and issuing certificates that enable adversaries to impersonate
legitimate users."
  
  desc  "check", "
    Review the web server deployed configuration to determine if the web server
  will accept client certificates issued by unapproved PKIs. The authoritative
  list of DoD-approved PKIs is published at
  http://iase.disa.mil/pki-pke/interoperability.

  Check for the following:
  #grep ”ssl_client_certifcate” directive in the http and server context of the 
  nginx.conf file and any separated include configuration file.

  Examine the contents of this file to determine if the trusted Cas are DoD approved. 
  If the trusted CA that is used to authenticate users to the website does not lead 
  to an approved DoD CA, this is a finding.
  "
  desc  "fix", "Configure the web server’s trust store to trust only DoD-approved PKIs 
  (e.g., DoD PKI, DoD ECA, and DoD-approved external partners)."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000427-WSR-000186"
  tag "gid": "V-56027"
  tag "rid": "SV-70281r2_rule"
  tag "stig_id": "SRG-APP-000427-WSR-000186"
  tag "fix_id": "F-60905r1_fix"
  tag "cci": ["CCI-002470"]
  tag "nist": ["SC-23 (5)", "Rev_4"]

  nginx_conf_handle = nginx_conf(input('conf_path'))

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  nginx_conf_handle.http.entries.each do |http|
    describe http.params['ssl_client_certificate'] do
      it { should_not be_nil }
    end
    http.params['ssl_client_certificate'].each do |cert|
      describe x509_certificate(cert.join) do
        it { should_not be_nil }

        its('subject.C') { should cmp 'US' }
        its('subject.O') { should cmp 'U.S. Government' }
      end
      describe x509_certificate(cert.join).subject.CN[0..2] do
        it { should be_in input('dod_approved_pkis') }
      end
    end unless http.params['ssl_client_certificate'].nil?
  end

  nginx_conf_handle.servers.entries.each do |server|
    server.params['ssl_client_certificate'].each do |cert|
      describe x509_certificate(cert.join) do
        it { should_not be_nil }

        its('subject.C') { should cmp 'US' }
        its('subject.O') { should cmp 'U.S. Government' }
      end
      describe x509_certificate(cert.join).subject.CN[0..2] do
        it { should be_in input('dod_approved_pkis') }
      end
    end unless server.params['ssl_client_certificate'].nil?
  end
end

