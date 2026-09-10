Gem::Specification.new do |spec|
  spec.name          = "apexmail"
  spec.version       = "1.0.0"
  spec.summary       = "Official Ruby SDK for the ApexMail transactional email API"
  spec.description   = "Send transactional email, manage domains, webhooks and templates via the ApexMail API."
  spec.authors       = ["ApexMail"]
  spec.homepage      = "https://apexmail.ee"
  spec.license       = "MIT"

  spec.metadata = {
    "source_code_uri" => "https://github.com/Bel-Consulting-OU/ApexMail/tree/main/packages/sdk-ruby",
    "changelog_uri"   => "https://github.com/Bel-Consulting-OU/ApexMail/blob/main/packages/sdk-ruby/CHANGELOG.md",
    "bug_tracker_uri" => "https://github.com/Bel-Consulting-OU/ApexMail/issues",
  }

  spec.required_ruby_version = ">= 3.0"

  spec.add_dependency "json", ">= 2.5", "< 4"

  spec.files = Dir["lib/**/*.rb", "README.md"]
  spec.require_paths = ["lib"]
end
