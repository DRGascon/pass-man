#!/usr/bin/env ruby

require 'logger'

logger = Logger.new('sys.log','daily')
logger.progname = 'pass-man'
logger.level = Logger::INFO
logger.info "Logger created" 
