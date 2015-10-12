require 'uri_signature'

describe URISignature do
  before(:all) do
    ENV["HMAC_SIGNATURE_KEY"] = "abc123"
  end

  before(:each) do
    now = Time.at(1444620194).utc
    allow(Time).to receive(:now).and_return(now)
  end

  describe '.sign' do
    let(:signed) { URISignature.sign(uri).to_s }
    let(:uri) { "https://thing.com?a=123&identity_uuid=fbd960b8-8d9f-4475-8fa1-cde8bcd507e0" }

    it 'signs the URI' do
      expect(signed).to eq("https://thing.com?a=123&identity_uuid=fbd960b8-8d9f-4475-8fa1-cde8bcd507e0&signature=42531af2672e0bd29d4fa4a3beb5ce6760bebf02&signature_expires=1444620494")
    end

    context 'with params not in alphabetical order' do
      let(:uri) { "https://thing.com?identity_uuid=fbd960b8-8d9f-4475-8fa1-cde8bcd507e0&a=123" }

      it 'reorders the params then signs' do
        expect(signed).to eq("https://thing.com?a=123&identity_uuid=fbd960b8-8d9f-4475-8fa1-cde8bcd507e0&signature=42531af2672e0bd29d4fa4a3beb5ce6760bebf02&signature_expires=1444620494")
      end
    end
  end

  describe '.valid?' do
    let(:result) { URISignature.valid?(uri) }

    context 'with a correct signature' do
      let(:uri) { "https://thing.com?a=123&identity_uuid=fbd960b8-8d9f-4475-8fa1-cde8bcd507e0&signature=42531af2672e0bd29d4fa4a3beb5ce6760bebf02&signature_expires=1444620494" }

      it 'returns true' do
        expect(result).to eq(true)
      end
    end

    context 'with an incorrect signature' do
      let(:uri) { "https://thing.com?a=123&identity_uuid=fbd960b8-8d9f-4475-8fa1-cde8bcd507e0&signature=42531af2672e0bd29d4fa4a3beb5ce6760bebf123&signature_expires=1444620494" }

      it 'raises InvalidSignatureError' do
        expect { result }.to raise_error(URISignature::InvalidSignatureError)
      end
    end

    context 'with an expired signature' do
      let(:uri) { "https://thing.com?a=123&identity_uuid=fbd960b8-8d9f-4475-8fa1-cde8bcd507e0&signature=9fe13a9f22e16dd0fec4456a2b37fa39c46a6d36&signature_expires=1344620494" }

      it 'returns ExpiredSignatureError' do
        expect { result }.to raise_error(URISignature::ExpiredSignatureError)
      end
    end
  end
end
