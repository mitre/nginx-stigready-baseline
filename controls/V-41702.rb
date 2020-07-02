# encoding: UTF-8

control "V-41702" do
  title "The web server must have Web Distributed Authoring (WebDAV) disabled."
  desc  "A web server can be installed with functionality that, just by its
nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to
the HTTP protocol that, when developed, was meant to allow users to create,
change, and move documents on a server, typically a web server or web share.
Allowing this functionality, development, and deployment is much easier for web
authors.

    WebDAV is not widely used and has serious security concerns because it may
allow clients to modify unauthorized files on the web server.
  "
  desc  "rationale", ""
  desc  "check", "
  Review the web server documentation and deployment configuration to
  determine if Web Distributed Authoring (WebDAV) is enabled.

  Execute the following command: 

  # nginx -V

  Verify the ‘ngx_http_dav_module’ module is not installed.
  "
  desc  "fix", "Use the configure script (available in the nginx download package) to 
  exclude the 'ngx_http_dav_module' module by using the --without {module_name} option."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000085"
  tag "gid": "V-41702"
  tag "rid": "SV-54279r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000085"
  tag "fix_id": "F-47161r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  describe nginx do
    its('modules') { should_not include 'ngx_http_dav' }
  end
end

