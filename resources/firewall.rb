# frozen_string_literal: true

# A firewall provides actions to manage the entire firewall
# No default action is provided so that all actions must be explicitly specified
# disable_external_rules ensures all rules that are not managed by chef are disabled
# delete_external_rules ensures all rules that are not managed by chef are deleted
# Both disable and delete actions respect the whitelist attributes:
#  1) node['win_firewall']['firewall_to_whitelist_groups']
#  2) node['win_firewall']['firewall_to_whitelist_rules']
resource_name :firewall
provides :firewall, os: 'windows'

# The name property, used to identify the firewall
property :name, String, name_property: true
property :log_file, String, default: 'C:/chef/log/win_firewall.log'

extend ::Firewall::Helper

action :create do
  create_helper(@new_resource)
end

action :log_scripts do
  log_scripts_helper(@new_resource)
end

action :disable_external_rules do
  disable_external_rules_helper(@new_resource)
end

action :delete_external_rules do
  delete_external_rules_helper(@new_resource)
end

action :delete_external_disabled_rules do
  delete_external_disabled_rules_helper(@new_resource)
end

action_class.class_eval do
  include ::Firewall::Helper

  def create_helper(new_resource)
    ensure_firewall_exists(new_resource)
  end

  def log_scripts_helper(new_resource)
    ensure_log_scripts_exist(new_resource)
  end

  def disable_external_rules_helper(new_resource)
    ensure_external_rules_are_disabled(new_resource)
  end

  def delete_external_rules_helper(new_resource)
    ensure_no_external_rules_exist(new_resource)
  end

  def delete_external_disabled_rules_helper(new_resource)
    ensure_no_external_disabled_rules_exist(new_resource)
  end
end
