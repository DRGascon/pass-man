require 'rake'
require 'rake/testtask'

Rake::TestTask.new do |t|
    t.test_files = FileList["./unit-tests/*.rb"]
    t.warning = true
end
