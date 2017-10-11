# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ipip"

describe LogStash::Filters::Ipip do
  describe "Test ip 8.8.8.8" do
    let(:config) do <<-CONFIG
      filter {
        ipip {
          source => "ip"
        }
      }
    CONFIG
    end

    sample("ip" => "8.8.8.8") do
      expect(subject).to include("ipip")
      expect(subject.get('ipip')).not_to be_empty  # todo
      expect(subject.get("geoip")["asn"]).to eq(15169)
      expect(subject.get("geoip")["as_org"]).to eq("Google Inc.")
    end
  end
end
