# encoding: utf-8
require "lru_redux"
require "logstash/filters/base"
require "logstash/namespace"


class IPIP
  def initialize(db_path)
      @db_path = db_path
      @ip_db = File.open @db_path, 'rb'
      @offset = @ip_db.read(4).unpack('Nlen')[0]
      @index = @ip_db.read(@offset - 4)
      @max_comp_length = @offset - 262144 - 4
  end

  def four_number(ip)
      result = begin
          fn = ip.split(".").map(&:to_i)
          raise "ip is no valid" if fn.length != 4 || fn.any?{ |d| d < 0 || d > 255}
          fn
      end
      return result
  end

  def ip2long(ip)
      result = ::IPAddr.new(ip).to_i
      return result
  end

  def packed_ip(ip)
      ip2long = ::IPAddr.new(ip).to_i
      result = [ ip2long ].pack 'N'
      return result
  end

  def seek(_offset, length)
      result = IO.read(@db_path, length, @offset + _offset - 262144).split(/\t/)
      return result
  end

  def find(ip)
      packed = packed_ip(ip)
      numbers = four_number(ip)
      tmp_offset = numbers[0] * 256 + numbers[1] * 4
      start = @index[tmp_offset..(tmp_offset + 3)].unpack("V")[0] * 9 + 262144

      index_offset = -1

      while start < @max_comp_length
          if @index[start..(start + 3)] >= packed
              index_offset = "#{@index[(start + 4)..(start + 6)]}\x0".unpack("V")[0]
              index_length = @index[(start + 7)..(start + 8)].unpack("n")[0]
              break
          end
          start += 9
      end

      return nil unless index_offset

      result = seek(index_offset, index_length).map do |s|
          s.encode("UTF-8", "UTF-8")
      end

      data = {
          country: result[0].to_s.empty? ? "N/A" : result[0],
          province: result[1].to_s.empty? ? "N/A" : result[1],
          city: result[2].to_s.empty? ? "N/A" : result[2],
          district: result[3].to_s.empty? ? "N/A" : result[3],
          isp: result[4].to_s.empty? ? "N/A" : result[4],
          timezone_name: result[7].to_s.empty? ? "N/A" : result[7],
          timezone: result[8].to_s.empty? ? "N/A" : result[8],
          zip: result[9].to_s.empty? ? "N/A" : result[9],
          phonecode: result[10].to_s.empty? ? "N/A" : result[10],
          countrycode: result[11].to_s.empty? ? "N/A" : result[11],
          region: result[12].to_s.empty? ? "N/A" : result[12],
          location: {
              lon: result[6].to_f.empty? ? 0.0 : result[6],
              lat: result[5].to_f.empty? ? 0.0 : result[5]
          }
      }
  end
end


class LogStash::Filters::Ipip < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #    ipip {
  #     source => "8.8.8.8"
  #     target => "geoip"
  #   }
  # }
  #
  config_name "ipip"
  
  # Replace the message with this value.
  config :source, :validate => :string, :require => true
  config :target, :validate => :string, :default => 'geoip'
  config :database, :validate => :path, :default => '/var/lib/ipip.net/ipip.datx'
  config :lru_cache_size, :validate => :number, :default => 10000
  config :tag_on_failure, :validate => :array, :default => ["_ipip_lookup_failure"]

  public
  def register
    if !File.exists?(@database)
      raise "You must specify 'database => ...' in your geoip filter (I looked for '#{@database}')"
    end

    @db = IPIP.new(@database)
    @lookup_cache = LruRedux::ThreadSafeCache.new(10000)
    @lookup_cache.max_size = @lru_cache_size

    @logger.info("Using geoip database", :path => @database)
  end

  public
  def filter(event)
    ip = event.get(@source)
    return if ip.nil? || ip.empty?

    cached = @lookup_cache[ip]
    if cached
      data = cached
    else
      begin
        data = @db.find ip
      rescue Exception => e
        @logger.error("Unknown error while looking up IPIP data", :exception => e, :field => @field, :event => event)
      end
    end

    if data.nil?
      @tag_on_failure.each{|tag| event.tag(tag)}
    else
      event.set(@target, data)
      @lookup_cache[ip] = data
    end

    filter_matched(event)
  end # def filter

end # class LogStash::Filters::Ipip
