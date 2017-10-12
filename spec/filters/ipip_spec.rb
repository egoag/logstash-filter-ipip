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
      expect(subject).to include("ipip")
      expect(subject.get('ipip')).not_to be_empty
      expect(subject.get('ipip')["location"]).not_to be_empty
      expect(subject.get("ipip")["country"]).to eq('China')
      expect(subject.get("ipip")["province"]).to eq("Beijing")
      expect(subject.get("ipip")["city"]).to eq("Beijing")
      expect(subject.get("ipip")["district"]).not_to be_empty
      expect(subject.get("ipip")["isp"]).not_to be_empty
      expect(subject.get("ipip")["latitude"]).not_to be_empty
      expect(subject.get("ipip")["longitude"]).not_to be_empty
      expect(subject.get("ipip")["timezone_name"]).to eq("Asia/Shanghai")
      expect(subject.get("ipip")["timezone"]).to eq("UTC+8")
      expect(subject.get("ipip")["zip"]).to eq("110000")
      expect(subject.get("ipip")["phonecode"]).to eq("86")
      expect(subject.get("ipip")["countrycode"]).to eq("CN")
      expect(subject.get("ipip")["region"]).to eq("AP")
    end
  end
end
