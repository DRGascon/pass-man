require 'logger'

module Logging

    def logger
        Logging.logger
    end

    def self.logger
        @logger ||= Logger.new("sys.log", "daily")
    end
end

