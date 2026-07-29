# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# Deterministic CBOR (RFC 8949 §4.2.1) for N-AALP — the C1 codec.
#
# An independent Ruby implementation of the same deterministic profile the Go, Rust and
# Python reference implementations produce: shortest-form integer heads, no indefinite
# lengths, canonical (bytewise-ascending, by encoded key) map ordering, no duplicate keys.
# The content id is multihash(0x20 sha2-384, 0x30 [48], SHA-384(body)) over the body (§2.3).
require 'openssl'

module Naalp
  module CBOR
    class NonCanonical < StandardError
      def kind; "NonCanonical"; end
    end

    # --- value model (mirrors the Go/Rust/Python cbor.Value variants) ---

    class U            # unsigned integer (major 0)
      attr_reader :v
      def initialize(v); @v = Integer(v); end
    end
    class N            # negative integer (major 1); v is the negative value itself
      attr_reader :v
      def initialize(v); @v = Integer(v); end
    end
    class B            # byte string (major 2)
      attr_reader :v
      def initialize(v); @v = v.dup.force_encoding(Encoding::BINARY); end
    end
    class T            # text string (major 3)
      attr_reader :v
      def initialize(v); @v = v.to_s; end
    end
    class A            # array (major 4)
      attr_reader :items
      def initialize(items); @items = items.to_a; end
    end
    class M            # map (major 5); pairs is an array of [key_value, value]
      attr_reader :pairs
      def initialize(pairs); @pairs = pairs.to_a; end
    end
    class Tag          # tag (major 6)
      attr_reader :n, :content
      def initialize(n, content); @n = Integer(n); @content = content; end
    end

    module_function

    def head(major, n)
      raise NonCanonical, "negative length/arg" if n < 0
      if n < 24
        [(major << 5) | n].pack("C")
      elsif n < 256
        [(major << 5) | 24, n].pack("C*")
      elsif n < 65536
        [(major << 5) | 25].pack("C") + [n].pack("n")
      elsif n < 2**32
        [(major << 5) | 26].pack("C") + [n].pack("N")
      else
        [(major << 5) | 27].pack("C") + [n].pack("Q>")
      end
    end

    def encode(v)
      case v
      when U
        raise NonCanonical, "uint is negative" if v.v < 0
        head(0, v.v)
      when N
        head(1, -1 - v.v)
      when B
        head(2, v.v.bytesize) + v.v
      when T
        raw = v.v.dup.force_encoding(Encoding::UTF_8)
        raise NonCanonical, "text is not valid UTF-8" unless raw.valid_encoding?
        raw = raw.b
        head(3, raw.bytesize) + raw
      when A
        out = head(4, v.items.length).dup
        v.items.each { |i| out << encode(i) }
        out
      when M
        enc = v.pairs.map { |k, val| [encode(k), encode(val)] }
        enc.sort_by! { |kv| kv[0] }
        keys = enc.map { |k, _| k }
        raise NonCanonical, "duplicate map key" if keys.uniq.length != keys.length
        out = head(5, enc.length).dup
        enc.each { |k, val| out << k; out << val }
        out
      when Tag
        head(6, v.n) + encode(v.content)
      else
        raise TypeError, "not a cbor value: #{v.inspect}"
      end
    end

    # Cursor-based strict decoder. Returns [value, new_pos].
    def dec(data, pos)
      raise NonCanonical, "truncated" if pos >= data.bytesize
      ib = data.getbyte(pos)
      major = ib >> 5
      ai = ib & 0x1F
      raise NonCanonical, "indefinite length" if ai == 31
      if ai < 24
        arg = ai
        pos += 1
      elsif ai == 24
        raise NonCanonical, "truncated head" if pos + 2 > data.bytesize
        arg = data.getbyte(pos + 1)
        pos += 2
        raise NonCanonical, "non-shortest integer" if arg < 24
      elsif ai == 25
        raise NonCanonical, "truncated head" if pos + 3 > data.bytesize
        arg = data.byteslice(pos + 1, 2).unpack1("n")
        pos += 3
        raise NonCanonical, "non-shortest integer" if arg < 256
      elsif ai == 26
        raise NonCanonical, "truncated head" if pos + 5 > data.bytesize
        arg = data.byteslice(pos + 1, 4).unpack1("N")
        pos += 5
        raise NonCanonical, "non-shortest integer" if arg < 65536
      elsif ai == 27
        raise NonCanonical, "truncated head" if pos + 9 > data.bytesize
        arg = data.byteslice(pos + 1, 8).unpack1("Q>")
        pos += 9
        raise NonCanonical, "non-shortest integer" if arg < 2**32
      else
        raise NonCanonical, "reserved additional-info"
      end

      case major
      when 0
        [U.new(arg), pos]
      when 1
        [N.new(-1 - arg), pos]
      when 2
        raise NonCanonical, "truncated byte string" if pos + arg > data.bytesize
        [B.new(data.byteslice(pos, arg)), pos + arg]
      when 3
        raise NonCanonical, "truncated text string" if pos + arg > data.bytesize
        raw = data.byteslice(pos, arg).force_encoding(Encoding::UTF_8)
        raise NonCanonical, "text is not valid UTF-8" unless raw.valid_encoding?
        [T.new(raw), pos + arg]
      when 4
        items = []
        arg.times do
          it, pos = dec(data, pos)
          items << it
        end
        [A.new(items), pos]
      when 5
        pairs = []
        prev = nil
        arg.times do
          before = pos
          k, pos = dec(data, pos)
          kbytes = data.byteslice(before, pos - before)
          val, pos = dec(data, pos)
          if !prev.nil? && (kbytes <=> prev) <= 0
            raise NonCanonical, "map keys out of order or duplicate"
          end
          prev = kbytes
          pairs << [k, val]
        end
        [M.new(pairs), pos]
      when 6
        content, pos = dec(data, pos)
        [Tag.new(arg, content), pos]
      else
        raise NonCanonical, "unsupported major type #{major}"
      end
    end

    def decode(data)
      data = data.dup.force_encoding(Encoding::BINARY)
      v, pos = dec(data, 0)
      raise NonCanonical, "trailing bytes after top-level item" if pos != data.bytesize
      v
    end

    def content_id(body)
      body = encode(body) if body.is_a?(U) || body.is_a?(N) || body.is_a?(B) ||
                             body.is_a?(T) || body.is_a?(A) || body.is_a?(M) || body.is_a?(Tag)
      prefix = [0x20, 0x30].pack("C*")
      prefix + OpenSSL::Digest::SHA384.digest(body)
    end
  end
end
