# UriSignature

A general purpose way of signing a URL when you need the signature to be added
to the URL. This is useful when you need to redirect a user from one service to
another and communicate information without any risk of tampering. It's based
on a shared secret and HMAC being used to sign the URL.

This could be used in techniques described in http://broadcast.oreilly.com/2009/12/principles-for-standardized-rest-authentication.html

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'uri_signature'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install uri_signature

## Usage

```ruby
pry(main)> require 'uri_signature'

pry(main)> signed_uri = URISignature.sign("http://foobar.com?my_trusted_information=helloworld", expiry: 300, key: "my_shared_secret_key").to_s
=> "http://foobar.com?my_trusted_information=helloworld&signature=b99f3d00610361be49327938b82802c933aa4fac&signature_expires=1444691758"

pry(main)> URISignature.valid?(signed_uri, key: "my_shared_secret_key")
=> true
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/uri_signature.

