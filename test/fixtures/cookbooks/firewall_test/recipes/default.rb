# frozen_string_literal: true

firewall 'default' do
  action :create
end

['dhcpv6', 'icmpv6', 'iphttps', 'ipv6', 'teredo'].each do |name_regex|
  firewall_rule_state name_regex do
    action :delete
    use_regex true
  end
end

firewall 'default' do
  action :log_scripts
end
