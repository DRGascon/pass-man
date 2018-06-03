#!/usr/bin/env ruby

require 'logger'
require 'singleton'

class PassLogger
    include Singleton
    attr_accessor :logger
    def self._load(str)
        instance.logger = Logger.new('sys.log','daily')
        instance.logger.level = Logger::INFO
        instance.logger.info('pass-man') { "Logger created" }
    end

end
