require 'uri_signature/version'
require 'addressable/uri'

class URISignature
  class SignatureError < StandardError; end
  class InvalidSignatureError < SignatureError; end
  class ExpiredSignatureError < SignatureError; end

  MINUTE = 60

  # Sign the given URI and return a signed URI.
  #
  # @param uri [String] a valid URI
  # @param expiry [Integer] How many seconds before the signature expires.
  # @param key [String] The key used to sign the uri
  # @return [String] The signed URI. The signature is added to the query
  #   params.
  def self.sign(uri, expiry: 5 * MINUTE, key: ENV['HMAC_SIGNATURE_KEY'])
    uri = Addressable::URI.parse(uri)

    query_values = (uri.query_values || {}).to_a

    query_values << ["signature_expires", (Time.now + expiry).tv_sec]

    # Sort by the key to guarantee URI is always constructed in the same way
    query_values = query_values.sort_by { |k, v| k }

    uri.query_values = query_values

    add_signature(uri, key).to_s
    uri.to_s
  end

  # Is the given uri correctly signed.
  #
  # @param uri [String]
  # @param raise_error [Boolean] Defaults to to true. Set this to false if
  #   you don't this to raise but rather return false if it's invalid. We
  #   default raise_error to true to be extra cautious as wanting to handle
  #   incorrectly signed callbacks is probably an edge case.
  # @return [TrueClass, FalseClass] Will return true if correctly signed.
  #   Otherwise it will raise. If you really don't want it to raise you can
  #   pass `raise_error: false`.
  # @raise [URISignature::SignatureError] if for any reason the
  #   signature is invalid. This can be disabled by setting
  #   `:raise_error => false`.
  def self.valid?(uri, key: ENV['HMAC_SIGNATURE_KEY'], raise_error: true)

    # First remove the signature
    comparison_uri = Addressable::URI.parse(uri).clone.tap do |u|
      query_values = u.query_values.clone
      query_values.delete("signature")
      u.query_values = query_values
    end

    # Then recalculate and add back in the signature
    add_signature(comparison_uri, key)

    # Compare the uri to the original
    if secure_compare(uri, comparison_uri.to_s)
      expires = Time.at(comparison_uri.query_values["signature_expires"].to_i)
      if expires < Time.now
        raise URISignature::ExpiredSignatureError, "The signature for #{uri} has expired."
      end
      true
    else
      raise URISignature::InvalidSignatureError, "Invalid signature provided in #{uri}."
    end
  end

  # @!private
  # This method is meant to only be used in this class. Do not use it externally.
  # @param uri [String]
  # @param key [String]
  def self.add_signature(uri, key)
    unsigned_uri = uri.to_s

    digest = OpenSSL::Digest.new('sha1')
    hmac = OpenSSL::HMAC.hexdigest(digest, key, unsigned_uri)

    query_values = uri.query_values.to_a
    query_values << ["signature", hmac]

    # Sort again to ensure consistency
    uri.query_values = query_values.sort_by { |k, v| k }
  end

  # Use a secure string comparison method to avoid timing attacks
  # (https://en.wikipedia.org/wiki/Timing_attack)
  def self.secure_compare(a, b)
    return false if a.empty? || b.empty? || a.bytesize != b.bytesize
    l = a.unpack "C#{a.bytesize}"

    res = 0
    b.each_byte { |byte| res |= byte ^ l.shift }
    res == 0
  end

  private_class_method :add_signature
  private_class_method :secure_compare
end
