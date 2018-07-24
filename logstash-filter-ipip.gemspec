Gem::Specification.new do |s|

  s.name            = 'logstash-filter-ipip'
  s.version         = '0.3.0'
  s.licenses        = ['Apache License (2.0)']
  s.summary         = "Adds geographical information about an IP address"
  s.description     = ""
  s.authors         = ["Gaoge"]
  s.email           = 'youyaochi@gmail.com'
  s.homepage        = "https://github.com/youyaochi/logstash-filter-ipip"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*', '*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT', 'maxmind-db-NOTICE.txt', 'docs/**/*']

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"
  s.add_runtime_dependency 'lru_redux', "~> 1.1.0", '>= 1.1.0'
  s.add_development_dependency 'logstash-devutils'
  s.add_development_dependency 'benchmark-ips'
end
