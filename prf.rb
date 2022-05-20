#! /usr/bin/env ruby

require 'openssl'
require 'optparse'
require 'securerandom'

@options = {
  key: "",
  label: "",
  seedlen: 32,
  seed: nil,
  length: 32,
  hash: 'sha256'
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{__FILE__} ..."

  opts.on('-kKEY', '--key=KEY', String, 'secret key') do |key|
    @options[:key] = key
  end
  opts.on('-rNUMBER', '--generate-random=NUMBER', Integer,
          "number of bytes for generated random seed " +
          "(do not use in conjunction with -s") do |seedlen|
    @options[:seedlen] = seedlen
  end
  opts.on('-sSEED', '--seed=SEED', String, 'random seed') do |seed|
    @options[:seed] = seed
  end
  opts.on('-lNUMBER', '--length=NUMBER', Integer, 'output length') do |len|
    @options[:length] = len
  end
  opts.on('-h', '--hash=NAME', String,
          "Name of hash function to use. The function must be supported " +
          "by OpenSSL. Default is #{@options[:hash]}.") do |hash|
    @options[:hash] = hash
  end
end.parse!

MAXCOL=8
begin
  DIGEST = OpenSSL::Digest.new(@options[:hash])
rescue
  STDERR.puts "E: Unsupported hash function '#{@options[:hash]}'"
  exit 1
end

def HMAC_hash(secret, data)
  OpenSSL::HMAC.digest(DIGEST, secret, data).force_encoding("US-ASCII")
end

def P_hash(secret, seed, maxlen)
  a = seed
  result = "".force_encoding("US-ASCII")
  nextA = ->(prev_a) { HMAC_hash(secret, prev_a); }
  while result.length < maxlen
    a = nextA.call(a)
    result += HMAC_hash(secret, a + seed)
  end
  result[0,maxlen]
end

def PRF(secret, label, seed, maxlen)
  P_hash(secret.force_encoding("US-ASCII"),
         label.force_encoding("US-ASCII")+seed.force_encoding("US-ASCII"),
         maxlen)
end

def hexdump(str)
  cols = 0
  str.each_byte do |c|
    printf "0x%02x" % c
    if cols < MAXCOL-1
      printf ", "
      cols += 1
    else
      printf ",\n"
      cols = 0
    end
  end
  puts unless cols == 0
end

length = @options[:length]
secret = @options[:key]
label = @options[:label]

if @options[:seed].nil?
  seedlen = @options[:seedlen]
  random = SecureRandom.random_bytes(seedlen)
else
  random = @options[:seed]
end

printf "secret="
hexdump secret
puts if secret.empty?

printf "label="
hexdump label
puts if label.empty?

printf "random="
hexdump random
puts if random.empty?

puts "length=#{length}"

hexdump PRF(secret, label, random, length)
