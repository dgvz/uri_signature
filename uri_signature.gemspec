# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'uri_signature/version'

Gem::Specification.new do |spec|
  spec.name          = "uri_signature"
  spec.version       = UriSignature::VERSION
  spec.authors       = ["Dylan Griffith"]
  spec.email         = ["dyl.griffith@gmail.com"]

  spec.summary       = %q{A general purpose way of signing a URL when you need the signature to be added to the URL.}
  spec.description   = %q{A general purpose way of signing a URL when you need the signature to be added to the URL.}
  spec.homepage      = "https://github.com/dgvz/uri_signature"

  # Prevent pushing this gem to RubyGems.org by setting 'allowed_push_host', or
  # delete this section to allow pushing this gem to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "addressable"

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec"
end
