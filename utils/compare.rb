# A comparision operation that always takes the same amount of time
# Taken from: ruby's documentation site


module Utils

    ############################################################################
    # Compare two arrays comparing each byte to make sure we don't leak any 
    # information about the comparison
    ############################################################################
    def equal_time_compare(a, b)
        unless a.length == b.length
            return false
        end
        cmp = b.bytes.to_a
        result = 0
        a.bytes.each_with_index { |value, index|
            result |= c ^ cmp[i]
        }
        result == 0
    end
end

