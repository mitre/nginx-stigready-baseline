control 'V-56005' do
  title "Web server cookies, such as session cookies, sent to the client using
SSL/TLS must not be compressed."
  desc  "A cookie is used when a web server needs to share data with the
client's browser. The data is often used to remember the client when the client
returns to the hosted application at a later date. A session cookie is a
special type of cookie used to remember the client during the session. The
cookie will contain the session identifier (ID) and may contain authentication
data to the hosted application. To protect this data from easily being
compromised, the cookie can be encrypted.

    When a cookie is sent encrypted via SSL/TLS, an attacker must spend a great
deal of time and resources to decrypt the cookie. If, along with encryption,
the cookie is compressed, the attacker can now use a combination of plaintext
injection and inadvertent information leakage through data compression to
reduce the time needed to decrypt the cookie. This attack is called Compression
Ratio Info-leak Made Easy (CRIME).

    Cookies shared between the web server and the client when encrypted should
not also be compressed.
  "

  desc 'check', "Review the web server documentation and deployed configuration
  to determine whether cookies are being sent to the client using SSL/TLS.

  If the transmission is through a SSL/TLS connection, but the cookie is not
  being compressed, this finding is Not Applicable.

  If it is determined that the web server is not required to perform session
  management, this check is Not Applicable.

  SSL/TLS compression has been disabled by default since NGINX version 1.3.2.
  Execute the following command to get the current version of NGINX running:
    # nginx -v

    If the current version of NGINX running is older than 1.3.2, this is a finding.
  "
  desc 'fix', "Upgrade to the lastest stable version of NGINX web server to
  ensure Web server cookies, such as session cookies, are not compressed."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000439-WSR-000153'
  tag "gid": 'V-56005'
  tag "rid": 'SV-70259r2_rule'
  tag "stig_id": 'SRG-APP-000439-WSR-000153'
  tag "fix_id": 'F-60883r1_fix'
  tag "cci": ['CCI-002418']
  tag "nist": %w(SC-8 Rev_4)

  if input('performs_session_management') == 'false'
    impact 0.0
    describe 'This check is NA because session management is not required.' do
      skip 'This check is NA because session management is not required.'
    end
  else
    describe nginx do
      its('version') { should cmp >= '1.3.2' }
    end
  end
end
