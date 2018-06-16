################################################################################
# A set of utilities around string manipulation
################################################################################

################################################################################
# Convert an array to string, or do nothing if it's nil
#
# Sets encoding to UTF-8 mainly to help working with JSON generation
################################################################################

module Utils
    def self.array_to_str(array)
        array.nil? ? nil : array.unpack("H*").first.force_encoding('UTF-8')
    end
end
