require 'rubygems'
require 'bacon'
require 'facon'
require 'fileutils'

if ENV['DEBUG'] and ENV['DEBUG'] != ''
  STDERR.puts "Enabling debugger for spec runs..."
  require 'rubygems'
  require 'ruby-debug'
  Debugger.start
end

$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib')))

# local target directory, integration spec workspace
def deployment_root
  '/tmp/wd-integration-target/destination/'
end

# allow defining an integration spec block
def integration_spec(&block)
  yield if ENV['INTEGRATION'] and ENV['INTEGRATION'] != ''
end

# reset the deployment directory for integration specs
def setup_deployment_area
  FileUtils.rm_rf(deployment_root)
  File.umask(0)
  Dir.mkdir(deployment_root, 0777)
  Dir.mkdir(deployed_file('log'), 0777)
end

# run a wd setup using the provided arguments string
def run_setup(arguments, debugging = true)
  wd_path  = File.join(File.dirname(__FILE__), '..', 'bin', 'wd')
  lib_path = File.join(File.dirname(__FILE__), '..', 'lib')
  debug = debugging ? '--debug' : ''
  system("/usr/bin/env ruby -I #{lib_path} -r whiskey_disk -rubygems #{wd_path} setup #{debug} #{arguments} > #{integration_log} 2> #{integration_log}")
end

def integration_log
  deployed_file('log/out.txt')
end

# run a wd setup using the provided arguments string
def run_deploy(arguments, debugging = true)
  wd_path  = File.join(File.dirname(__FILE__), '..', 'bin', 'wd')
  lib_path = File.join(File.dirname(__FILE__), '..', 'lib')
  debug = debugging ? '--debug' : ''
  status = system("/usr/bin/env ruby -I #{lib_path} -r whiskey_disk -rubygems #{wd_path} deploy #{debug} #{arguments} > #{integration_log} 2> #{integration_log}")
  status
end

# build the correct local path to the deployment configuration for a given scenario
def scenario_config(path)
  File.join(File.dirname(__FILE__), '..', 'scenarios', path)
end

# clone a git repository locally (as if a "wd setup" had been deployed)
def checkout_repo(repo_name, branch = nil)
  repo_path = File.expand_path(File.join(File.dirname(__FILE__), '..', 'scenarios', 'git_repositories', "#{repo_name}.git"))
  system("cd #{deployment_root} && git clone #{repo_path} >/dev/null 2>/dev/null")
  checkout_branch(repo_name, branch)
end

def checkout_branch(repo_name, branch = nil)
  return unless branch
  system("cd #{deployment_root}/#{repo_name} && git checkout #{branch} >/dev/null 2>/dev/null")
end

def jump_to_initial_commit(path)
  system(%Q(cd #{File.join(deployment_root, path)} && git reset --hard `git log --oneline | tail -1 | awk '{print $1}'` >/dev/null 2>/dev/null))
end

def run_log
  File.readlines(integration_log)
end

def deployed_file(path)
  File.join(deployment_root, path)
end

def dump_log
  STDERR.puts("\n\n\n" + File.read(integration_log) + "\n\n\n")
end

def current_branch(path)
  `cd #{deployed_file(path)} && git branch`.split("\n").grep(/^\*/).first.sub(/^\* /, '')
end

def xml_fixture(name)
  File.open(File.expand_path("../fixtures/#{name}.xml", __FILE__))
end

def stub_autoscaling_response
  stub_request(:post, "https://autoscaling.us-west-1.amazonaws.com/").
    with(
      :body => "Action=DescribeAutoScalingGroups&Version=2011-01-01",
      :headers => {
        'Accept'               => '*/*',
        'Accept-Encoding'      => '',
        'Authorization'        => /^\s*(#|$)|\b(Credential|SignedHeaders|Signature)\b/,
        'Content-Length'       => '51',
        'Content-Type'         => 'application/x-www-form-urlencoded; charset=utf-8',
        'Host'                 => 'autoscaling.us-west-1.amazonaws.com',
        'User-Agent'           => 'aws-sdk-ruby2/2.0.31 ruby/2.0.0 x86_64-darwin13.1.0',
        'X-Amz-Content-Sha256' => /[0-9a-z]{64}/,
        'X-Amz-Date'           => /[0-9A-Z]{16}/
      }).to_return(
        :status => 200,
        :body => xml_fixture('describe_auto_scaling_groups'),
        :headers => {:content_type => 'application/xml'}
      )
end

def stub_ec2_instances_response
  stub_request(:post, "https://ec2.us-west-1.amazonaws.com/").
    with(
      :body => "Action=DescribeInstances&InstanceId.1=i-100e50e0&Version=2014-10-01",
      :headers => {
        'Accept'               => '*/*',
        'Accept-Encoding'      => '',
        'Authorization'        => /^\s*(#|$)|\b(Credential|SignedHeaders|Signature)\b/,
        'Content-Length'       => '67',
        'Content-Type'         => 'application/x-www-form-urlencoded; charset=utf-8',
        'Host'                 => 'ec2.us-west-1.amazonaws.com',
        'User-Agent'           => 'aws-sdk-ruby2/2.0.31 ruby/2.0.0 x86_64-darwin13.1.0',
        'X-Amz-Content-Sha256' => /[0-9a-z]{64}/,
        'X-Amz-Date'           => /[0-9A-Z]{16}/
      }).to_return(
        :status => 200,
        :body => xml_fixture('describe_ec2_instances'),
        :headers => {:content_type => 'application/xml'}
      )
end