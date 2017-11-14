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

    sample("ip" => "119.75.216.20") do
      expect(subject).to include("geoip")
      expect(subject.get('geoip')).not_to be_empty
      expect(subject.get('geoip')["location"]).not_to be_empty
      expect(subject.get("geoip")["country"]).to eq('China')
      expect(subject.get("geoip")["province"]).to eq("Beijing")
      expect(subject.get("geoip")["city"]).to eq("Beijing")
      expect(subject.get("geoip")["district"]).not_to be_empty
      expect(subject.get("geoip")["isp"]).not_to be_empty
      expect(subject.get("geoip")["latitude"]).not_to be_empty
      expect(subject.get("geoip")["longitude"]).not_to be_empty
      expect(subject.get("geoip")["timezone_name"]).to eq("Asia/Shanghai")
      expect(subject.get("geoip")["timezone"]).to eq("UTC+8")
      expect(subject.get("geoip")["zip"]).to eq("110000")
      expect(subject.get("geoip")["phonecode"]).to eq("86")
      expect(subject.get("geoip")["countrycode"]).to eq("CN")
      expect(subject.get("geoip")["region"]).to eq("AP")
    end
  end
end
