require 'yaml'
require 'uri'
require 'open-uri'
autoload :Aws, 'aws-sdk'

class WhiskeyDisk
  class Config
    class << self
      def environment_name
        return false unless (ENV['to'] && ENV['to'] != '')
        return ENV['to'] unless ENV['to'] =~ /:/
        ENV['to'].split(/:/)[1]
      end

      def specified_project_name
        return false unless (ENV['to'] && ENV['to'] =~ /:/)
        ENV['to'].split(/:/).first
      end

      def override_project_name!(data)
        return if ENV['to'] && ENV['to'] =~ /:/
        ENV['to'] = data[environment_name]['project'] + ':' + ENV['to'] if data[environment_name]['project']
      end

      def path
        (ENV['path'] && ENV['path'] != '') ? ENV['path'] : false
      end

      def check_staleness?
        !!(ENV['check'] && ENV['check'] =~ /^(?:t(?:rue)?|y(?:es)?|1)$/)
      end

      def debug_ssh?
        !!(ENV['debug_ssh'] && ENV['debug_ssh'] =~ /^(?:t(?:rue)?|y(?:es)?|1)$/)
      end

      def debug_shell?
        !!(ENV['debug_shell'] && ENV['debug_shell'] =~ /^(?:t(?:rue)?|y(?:es)?|1)$/)
      end

      def debug_any?
        debug_shell? || debug_ssh?
      end
      alias_method :debug?, :debug_any?

      def domain_limit
        return false unless ENV['only'] and ENV['only'] != ''
        ENV['only']
      end

      def contains_rakefile?(path)
        File.exists?(File.expand_path(File.join(path, 'Rakefile')))
      end

      def find_rakefile_from_current_path
        original_path = Dir.pwd
        while (!contains_rakefile?(Dir.pwd))
          return File.join(original_path, 'config') if Dir.pwd == '/'
          Dir.chdir('..')
        end
        File.join(Dir.pwd, 'config')
      ensure
        Dir.chdir(original_path)
      end

      def base_path
        return path if path
        find_rakefile_from_current_path
      end

      def valid_path?(path)
        if path
          uri = URI.parse(path)
          return path if uri.scheme
          return path if File.file?(path)
        end

        false
      end

      def configuration_file
        return path if valid_path?(path)

        files = []

        files += [
          File.join(base_path, 'deploy', specified_project_name, "#{environment_name}.yml"),  # /deploy/foo/staging.yml
          File.join(base_path, 'deploy', "#{specified_project_name}.yml") # /deploy/foo.yml
        ] if specified_project_name

        files += [
          File.join(base_path, 'deploy', "#{environment_name}.yml"),  # /deploy/staging.yml
          File.join(base_path, "#{environment_name}.yml"), # /staging.yml
          File.join(base_path, 'deploy.yml') # /deploy.yml
        ]

        files.each { |file|  return file if File.exists?(file) }

        raise "Could not locate configuration file in path [#{base_path}]"
      end

      def configuration_data
        open(configuration_file) {|f| f.read }
      end

      def project_name
        specified_project_name || 'unnamed_project'
      end

      def repository_depth(data, depth = 0)
        raise 'no repository found' unless data.respond_to?(:has_key?)
        return depth if data.has_key?('repository')
        repository_depth(data.values.first, depth + 1)
      end

      # is this data hash a bottom-level data hash without an environment name?
      def needs_environment_scoping?(data)
        repository_depth(data) == 0
      end

      # is this data hash an environment data hash without a project name?
      def needs_project_scoping?(data)
        repository_depth(data) == 1
      end

      def add_environment_scoping(data)
        return data unless needs_environment_scoping?(data)
        { environment_name => data }
      end

      def add_project_scoping(data)
        return data unless needs_project_scoping?(data)
        override_project_name!(data)
        { project_name => data }
      end

      def localize_domain_list(list)
        [ list ].flatten.collect { |d| (d.nil? or d == '') ? 'local' : d }
      end

      def compact_list(list)
        [ list ].flatten.delete_if { |d| d.nil? or d == '' }
      end

      def set_if_present(row, key, domain_hash)
        value     = domain_hash[key.to_s] || domain_hash[key]
        if value.is_a?(Array) || key.to_s == 'roles'
          value   = compact_list(value)
        end
        row[key]  = value unless Array(value).empty? || value == ''
        row
      end

      def whitelisted_keys
        [:name, :roles, :region, :group_name, :user]
      end

      def normalize_domain(data)
        compacted = localize_domain_list(data)
        compacted = [ 'local' ] if compacted.empty?

        compacted.collect do |d|
          if d.respond_to?(:keys)
            row = {}
            whitelisted_keys.each { |key| row = set_if_present(row, key, d) }
            row
          else
            { :name => d }
          end
        end
      end

      def check_duplicates(project, target, domain_list)
        seen = {}
        domain_list.each do |domain|
          raise "duplicate domain [#{domain[:name]}] in configuration file for project [#{project}], target [#{target}]" if seen[domain[:name]]
          seen[domain[:name]] = true
        end
      end

      def normalize_domains(data)
        data.each_pair do |project, project_data|
          project_data.each_pair do |target, target_data|
            target_data['domain'] = check_duplicates(project, target, normalize_domain(target_data['domain']))
          end
        end
      end

      def normalize_data(data)
        normalize_domains(add_project_scoping(add_environment_scoping(data.clone)))
      end

      def load_data
        normalize_data(YAML.load(configuration_data))
      rescue Exception => e
        raise %Q{Error reading configuration file [#{configuration_file}]: "#{e}"}
      end

      def is_auto_scaling_group?(current)
        current['domain'][0][:name] == 'auto_scaling_group'
      end

      def region(current)
        current['domain'][0][:region] || 'us-east-1'
      end

      def autoscaling_client(current)
        @asg_client ||= Aws::AutoScaling::Client.new(region: region(current))
      end

      def ec2_client(current)
        @ec2_client ||= Aws::EC2::Client.new(region: region(current))
      end

      def asg_roles(current)
        current['domain'][0][:roles]
      end

      def user(current)
        current['domain'][0][:user]
      end

      def get_asg_nodes(current)
        asgs  = autoscaling_client(current).describe_auto_scaling_groups
        clean_project_name = project_name.split('.')[0]
        group_name         = "#{clean_project_name}-#{environment_name}"
        group = asgs[:auto_scaling_groups].detect do |asg|
          !!asg[:auto_scaling_group_name].match(/#{group_name}/)
        end
        unless group
          msg  = "\nNo members found for the `#{group_name}` group in the "
          msg += "`#{region(current)}` region\nAre you sure you the "
          msg += "group_name and region are correct and exist?"
          raise RuntimeError, msg, "ERROR"
        end

        instances = ec2_client(current).describe_instances(
          instance_ids: group[:instances].map { |i| i[:instance_id] }
        )
        
        get_instance_map_from_instances(current, instances)
      end

      def get_instance_map_from_instances(current, instances)
        instance_map = []
        
        instances[:reservations].each do |reservation|
          reservation[:instances].each do |instance|
            instance_map << {
              name: "#{user(current)}@#{instance[:private_ip_address]}",
              roles: asg_roles(current)
            }
          end
        end
        instance_map
      end

      def get_nodes_by_tags(current)
        instances = ec2_client(current).describe_instances(
          filters: build_filter_params_from_tags(current)
        )
        get_instance_map_from_instances(current, instances)
      end

      def build_filter_params_from_tags(current)
        # expected format: [{name:'tag:Name', values:['bakingAMI']}]
        filter_params = []
        current['node_tags'].each_pair do |k,v|
          filter_params << { name: "tag:#{k}", values: [v] }
        end
        filter_params
      end

      def parse_index_from_sub_name(name)
        if name == 'first'
          0
        elsif name == 'last'
          -1
        elsif name.include?('index_')
          name.gsub('index_','').to_i
        else
          nil
        end
      end

      def apply_subdomain_attributes(current, subdomains)
        subdomains.each do |sub|

          # get instance index
          index = parse_index_from_sub_name( sub[:name] )
          next if index.nil?

          # get instance from index
          instance = current['domain'][index]

          # get params subdomain attributes
          params = sub.reject{|k,v| k == :name }

          # add in params to instance config
          params.keys.each do |key|
            if instance.has_key?(key)
              instance[key] = instance[key] += params[key]
            else
              instance[key] = params[key]
            end
          end

        end
      end

      def filter_data(data)
        current = data[project_name][environment_name] rescue nil
        raise "No configuration file defined data for project `#{project_name}`, environment `#{environment_name}`" unless current

        current.merge!({
          'environment' => environment_name,
          'project' => project_name,
        })

        if is_scaling_instance?
          # running on instance command is called from
          current['domain'] = [{ name: 'local', roles: ["app", "assets"] }]

        elsif is_auto_scaling_group?(current)

          #
          #   pull 'subdomain' attributes from config
          #   i.e. attributes that should only apply to certain nodes
          #
          subdomains            = current['domain'][1..-1]
          
          current.merge!(node_tags) unless node_tags.nil?

          if use_all_nodes?
            # get the ASG nodes from AWS
            current['domain']     = get_asg_nodes(current)
          else
            # get nodes specified by --tags option
            current['domain']     = get_nodes_by_tags(current)
          end

          # apply subdomain attributes
          unless subdomains.nil? || subdomains.empty?
            apply_subdomain_attributes(current, subdomains)
          end

        end

        current['config_target'] ||= environment_name
        current
      end

      def is_scaling_instance?
        ENV['command'] == 'scale'
      end

      def use_all_nodes?
        node_tags.nil? || node_tags.empty?
      end

      def node_tags
        return nil if ENV['tags'].nil?
        
        @node_tags ||= { 
          'node_tags' => parse_node_tags(ENV['tags'])
        }
      end

      def parse_node_tags(tags)
        parsed_tags = {}
        tags.split(',').each do |tag|
          key = tag.split('=')[0]
          val = tag.split('=')[1]
          parsed_tags[key] = val
        end
        parsed_tags
      end

      def fetch
        raise "Cannot determine current environment -- try rake ... to=staging, for example." unless environment_name
        filter_data(load_data)
      end
    end
  end
end
