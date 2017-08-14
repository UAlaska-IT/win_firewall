# frozen_string_literal: true

if defined?(ChefSpec)
  ChefSpec::Runner.define_runner_method(:firewall)

  def create_firewall(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall, :create, resource)
  end

  def log_scripts_firewall(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall, :log_scripts, resource)
  end

  def disable_external_rules_firewall(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall, :disable_external_rules, resource)
  end

  def delete_external_rules_firewall(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall, :delete_external_rules, resource)
  end

  def delete_external_disabled_rules_firewall(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall, :delete_external_disabled_rules, resource)
  end

  ChefSpec::Runner.define_runner_method(:firewall_rule)

  def create_synchronize_firewall_rule(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall_rule, :create_synchronize, resource)
  end

  ChefSpec::Runner.define_runner_method(:firewall_rule_group)

  def enable_firewall_rule_group(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall_rule_state, :enable, resource)
  end

  def disable_firewall_rule_group(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall_rule_state, :disable, resource)
  end

  def delete_firewall_rule_group(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall_rule_state, :delete, resource)
  end

  ChefSpec::Runner.define_runner_method(:firewall_rule_state)

  def enable_firewall_rule_state(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall_rule_state, :enable, resource)
  end

  def disable_firewall_rule_state(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall_rule_state, :disable, resource)
  end

  def delete_firewall_rule_state(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:firewall_rule_state, :delete, resource)
  end
end
