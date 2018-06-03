#!/usr/bin/env ruby

require 'logger'

logger = Logger.new('sys.log','daily')

logger.level = Logger::INFO

logger.info('pass-man') { "Logger created" }

path = "a_non_existent_file"

begin
    File.foreach(path) do |line|
        unless line =~ /^(\w+) = (.*)$/
            logger.error("Line in wrong format: #{line.chomp}")
        end
    end
rescue => err
    logger.fatal("Caugh exception; exiting")
    logger.fatal(err)
end
