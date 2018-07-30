# frozen_string_literal: true

describe powershell('netsh advfirewall firewall show rule name=all verbose') do
  [/dhcpv6/i, /icmpv6/i, /iphttps/i, /ipv6/i, /teredo/i].each do |name_regex|
    its(:stdout) { should_not match(name_regex) }
  end
end


describe file('C:/chef/log/win_firewall.log') do
  it { should exist }
  it { should be_file }
end
