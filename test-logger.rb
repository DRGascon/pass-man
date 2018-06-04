require './utils/logging'

class LoggerTest

    def testMethod
        Logging.logger.warn "This is a test log"
    end
end

a = LoggerTest.new

a.testMethod
