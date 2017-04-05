# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'wor/authentication/version'
require 'date'

Gem::Specification.new do |spec|
  spec.name          = 'wor-authentication'
  spec.version       = Wor::Authentication::VERSION
  spec.platform      = Gem::Platform::RUBY
  spec.date          = Date.today
  spec.authors       = ['alebian', 'mishuagopian']
  spec.email         = ['alejandro.bezdjian@wolox.com.ar', 'michel.agopian@wolox.com.ar']

  spec.summary       = 'This gem lets you authenticate users in your API.'
  spec.description   = 'This gem lets you authenticate users in your API.'
  spec.homepage      = 'https://github.com/Wolox/wor-authentication'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec)/}) }
  spec.test_files    = spec.files.grep(%r{^(test|spec)/})
  spec.require_paths = ['lib']

  spec.add_dependency 'railties', '>= 4.1.0', '< 5.1'

  spec.add_development_dependency 'byebug', '~> 9.0'
  spec.add_development_dependency 'rubocop', '~> 0.47'
  spec.add_development_dependency 'bundler', '~> 1.13'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
end