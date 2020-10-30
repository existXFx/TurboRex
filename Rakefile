# encoding: utf-8

require 'rubygems'
require 'bundler'
begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end
require 'rake'

require 'juwelier'
Juwelier::Tasks.new do |gem|
  # gem is a Gem::Specification... see http://guides.rubygems.org/specification-reference/ for more options
  gem.name = "turborex"
  gem.homepage = "http://github.com/existXFx/turborex"
  gem.license = "GPLv3"
  gem.summary = %Q{A toolkit for exploring and exploiting MSRPC and COM.}
  gem.description = %Q{This gem is mainly a proof of concept for the topic "Automated Hunting for Cross-Server Xrefs in Microsoft RPC and COM" on Code Blue 2020. It is a locator for RPC server/client routines and COM interface methods/client calls, so it can be used to search for Cross-Server Xrefs scenes. In addition, it also has other functions such as ALPC client/server.}
  gem.email = "exist_sycsec@outlook.com"
  gem.authors = ["exist"]
  gem.files = ["lib/*.rb", "lib/*/*.rb", "lib/*/*/*.rb", "lib/*/*/*/*.rb", 'resources/*', 'resources/**/*', 'examples/*']
  # dependencies defined in Gemfile
end
Juwelier::RubygemsDotOrgTasks.new

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end

desc "Code coverage detail"
task :simplecov do
  ENV['COVERAGE'] = "true"
  Rake::Task['test'].execute
end

task :default => :test

require 'rdoc/task'
Rake::RDocTask.new do |rdoc|
  version = File.exist?('VERSION') ? File.read('VERSION') : ""

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "turborex #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
