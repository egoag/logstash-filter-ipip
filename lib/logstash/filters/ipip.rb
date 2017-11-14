# encoding: utf-8
require "lru_redux"
require "logstash/filters/base"
require "logstash/namespace"

# SeventeenMon Module
module SeventeenMon
  class IPDB

    private_class_method :new

    def ip_db_path
      @ip_db_path ||= File.expand_path'/var/lib/ipip.net/ipip.datx', __FILE__  # change this path to your .datx file
    end
    def ip_db
      @ip_db ||= File.open ip_db_path, 'rb'
    end

    def offset
      @offset ||= ip_db.read(4).unpack("Nlen")[0]
    end

    def index
      @index ||= ip_db.read(offset - 4)
    end

    def max_comp_length
      @max_comp_length ||= offset - 262144 - 4
    end

    def self.instance
      @instance ||= self.send :new
    end

    def seek(_offset, length)
      IO.read(ip_db_path, length, offset + _offset - 262144).split "\t"
    end
  end

  class IP
    attr_reader :ip

    # Initialize IP object
    #
    # == parameters:
    # params::
    #   Might contain address(hostname) and protocol, or just IP
    #
    # == Returns:
    # self
    #
    def initialize(params = {})
      @ip = params[:ip] ||
        Socket.getaddrinfo(params[:address], params[:protocol])[0][3]
    end

    def four_number
      @four_number ||= begin
        fn = ip.split(".").map(&:to_i)
        raise "ip is no valid" if fn.length != 4 || fn.any?{ |d| d < 0 || d > 255}
        fn
      end
    end

    def ip2long
      @ip2long ||= ::IPAddr.new(ip).to_i
    end

    def packed_ip
      @packed_ip ||= [ ip2long ].pack 'N'
    end

    def find
      tmp_offset = four_number[0] * 256 + four_number[1] * 4
      start = IPDB.instance.index[tmp_offset..(tmp_offset + 3)].unpack("V")[0] * 9 + 262144

      index_offset = -1

      while start < IPDB.instance.max_comp_length
        if IPDB.instance.index[start..(start + 3)] >= packed_ip
          index_offset = "#{IPDB.instance.index[(start + 4)..(start + 6)]}\x0".unpack("V")[0]
          index_length = IPDB.instance.index[(start + 7)..(start + 8)].unpack("n")[0]
          break
        end
        start += 9
      end

      return "N/A" unless index_offset

      result = IPDB.instance.seek(index_offset, index_length).map do |str|
        str.encode("UTF-8", "UTF-8")
      end

      data = {
        country: result[0] or 'n/a',
        province: result[1] or 'n/a',
        city: result[2] or 'n/a',
        district:result[3] or 'n/a',
        isp:result[4] or 'n/a',
        latitude:result[5] or 'n/a',
        longitude:result[6] or 'n/a',
        timezone_name:result[7] or 'n/a',
        timezone:result[8] or 'n/a',
        zip:result[9] or 'n/a',
        phonecode:result[10] or 'n/a',
        countrycode:result[11] or 'n/a',
        region:result[12] or 'n/a',
        location: {
          lon: result[6] or 'n/a',
          lat: result[5] or 'n/a'
        }
      }
    end
  end
end


module SeventeenMon
  require "socket"
  require "ipaddr"

  def self.find_by_ip(_ip)
    IP.new(ip: _ip).find
  end
end

SM = SeventeenMon

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Ipip < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #    {
  #        ipip => {
  #            "source" => "8.8.8.8"
  #            "target" => "geoip"
  #            "lru_cache_size" => "10000"
  #        }
  #    }
  # }
  #
  config_name "ipip"
  
  # Replace the message with this value.
  config :source, :validate => :string, :require => true
  config :target, :validate => :string, :default => 'geoip'
  config :lru_cache_size, :validate => :number, :default => 10000
  
  LOOKUP_CACHE = LruRedux::ThreadSafeCache.new(10000)

  public
  def register
    LOOKUP_CACHE.max_size = @lru_cache_size
  end # def register

  public
  def filter(event)
    ip = event.get(@source)
    return if ip.nil? || ip.empty?

    begin
      data = lookup_ipip ip
    rescue Exception => e
      @logger.error("Unknown error while looking up IPIP data", :exception => e, :field => @field, :event => event)
    end
    
    return unless data

    set_fields(event, data)

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter

  def lookup_ipip(ip)
    return unless ip

    cached = LOOKUP_CACHE[ip]
    return cached if cached

    data = nil
    data = SM.find_by_ip ip

    LOOKUP_CACHE[ip] = data
    data
  end

  def set_fields(event, data)
    event.set(@target, {}) if event.get(@target).nil?
    
    if !data.nil?
        data.each do |key, value|
          prefixed_key = "[%{target}][%{key}]" % {:target => target, :key => key}
          event.set(prefixed_key, value)
        end
    end
  end

end # class LogStash::Filters::Ipip
