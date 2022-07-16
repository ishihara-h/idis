#    idis.rb v1.0
#    Interactive disassembler for CDP1802 and i8080.
#    Copyright 2022 Hiroshi Ishihara
#
#    This file is part of idis.rb.
#
#    Idis.rb is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

require "curses"
require "./cdp1802.rb"
#require "./i8080.rb"

class Disasm
  attr_reader :label, :db, :dw, :comment
  attr_accessor :filename, :status
  module DefaultArray
    def [](x)
      self.fetch(x - @offset, 0)
    end
    def offset= (x)
      @offset = x
    end
    def offset
      @offset
    end
    def in_range(p)
      0 <= (p - @offset) && (p - @offset) < self.size
    end
  end

  def initialize(filename)
    @dw = {}
    @db = {}
    @label = {}
    @comment = {}
    @status = ""
    @filename = filename
    load
  end

  def load
    @data = if @filename && File.exist?(@filename)
      case File.extname(@filename)
      when ".hex"
        intel_hex
      else
        File.open(@filename, "rb").read.unpack("C*")
      end
    else
      @status = "cannot open file '#{filename}'"
      []
    end
    @data.extend DefaultArray
    @data.offset = 0
    load_cfg
  end

  def offset= (x)
    @data.offset = x
  end

  def offset
    @data.offset
  end

  def size
    @data.size
  end

  def in_range(x)
    @data.in_range(x)
  end

  def data
    @data
  end

  def get_a_line(p)
    if @data.in_range(p)
      opcode, opland, size = nemonic(p)
      [p, code(p, size), @label[p], opcode, opland, @comment[p], size]
    else
      nil
    end
  end

  def next_ad(p)
    size = nemonic(p)[2]
    if @data.in_range(p + size)
      p + size
    else
      @status = %Q|range err next(#{"%04x" % (p + size)})|
      p
    end
  end

  def pre_ad(p)
    if @data.in_range(p - 1)
      p - 1
    else
      @status = %Q|range error prev(#{"%04x" % (p - 1)})|
      p
    end
  end

  def save
    File.open("#{@filename}.cfg", "w") do |f|
      f.puts %Q|offset\n#{"%04X" % @data.offset}\t0|
      save_param(f, "dw", @dw)
      save_param(f, "db", @db)
      save_param(f, "label", @label)
      save_param(f, "comment", @comment)
    end
  end

  def source_save
    p = @data.offset
    File.open("#{@filename}.asm", "w") do |f|
      loop do
        if @data.in_range(p)
          address, code, label, opcode, opland, comment, size = get_a_line(p)
          if label then lab = ":" else lab = "" end
          if comment then comment = ";" + comment else comment = "" end
          f.puts %Q|#{"%04X" % address}\t#{code}\t#{label}#{lab}\t\t#{opcode}\t#{opland}\t#{comment}| 
          p += size
        else
          break
        end
      end
    end
  end

  private

  def code(p, size)
    result = ""
    0.upto(size - 1){|i| result << "%02X" % @data[p + i]}
    result
  end

  def intel_hex
    data = []
    File.open(@filename, "r") do |f|
      while l = f.gets
        if l !~ /:(.*)/
          @satus = "error format #{l}" 
          data = []
          break
        end
        length, a2, a1, type, *body = $1.scan(/.{2}/).map{|x| x.to_i(16)}
        address = a2 * 256 + a1
        case type
        when 0
          check = length + a2 + a1 + type
          0.upto (length - 1) do |i|
            data[address + i] = body[i]
            check += body[i]
            check &= 0xff
          end
          check += body[length]
          check &= 0xff
          if check != 0
            @status = "check sum error #{check}" 
            data = []
            break
          end
        when 1
          break
        when 2
        when 3
        when 4
        when 5
          @status = "error type= #{type}"
          data = []
          break
        else
          @status = "error format type #{type}"
          data = []
          break
        end
      end
    end
    data
  end

  def save_param(f, name, data)
    f.puts name
    data.each do |ad, n|
      f.puts "#{'%04X' % ad}\t#{n}"
    end
  end

  def load_cfg
    return if !File.exist?("#{@filename}.cfg")
    File.open("#{@filename}.cfg", "r") do |f|
      File.open("#{@filename}.err", "w") do |err|
        lno = 1
        while l = f.gets
          if l =~ /^(\w+)$/
            name = $1
          elsif l =~ /^([0-9A-Fa-f]+)\t(.+)$/
            case name
            when "dw"
              @dw[$1.to_i(16)] = $2.to_i
            when "db"
              @db[$1.to_i(16)] = $2.to_i
            when "label"
              @label[$1.to_i(16)] = $2
            when "comment"
              @comment[$1.to_i(16)] = $2
            when "offset"
              self.offset = $1.to_i(16)
            else
              @status = "config error file:#{@filename}.cfg line:#{lno} #{name} #{l}"
            end
          else
            @status = "config error file:#{@filename}.cfg line:#{lno} #{name} #{l}"
          end
          lno += 1
        end
      end
    end
  end
end

class MainWin
  attr_reader :cur_op, :cur_addr
  attr_accessor :max_line
  def initialize(disasm, win)
    @disasm = disasm
    @main_win = win.subwin(win.maxy - 2, win.maxx, 0, 0)
    @max_line = win.maxy - 2
    @sub_win = win.subwin(1, win.maxx, win.maxy - 2, 0)
    @cmd_win = win.subwin(1, win.maxx, win.maxy - 1, 0)
    @main_win.keypad(true)
    @cmd_win.keypad(true)
    @top_addr = @disasm.offset
    @cur_addr = 0
    @cur_line = 0
    @history = []
  end
  
  def resize(win)
    @main_win.resize(win.maxy - 2, win.maxx)
    @sub_win.resize(1, win.maxx)
    @sub_win.move(win.maxy - 2, 0)
    @cmd_win.resize(1, win.maxx)
    @cmd_win.move(win.maxy - 1, 0)
    @cmd_win.clear
    @cmd_win.refresh
    @max_line = win.maxy - 2
    if @cur_line > @max_line - 1
      @cur_line = @max_line - 1
    end
  end
  
  def update(disasm)
    cur = 0
    @main_win.clear
    p = @top_addr
    0.upto @max_line - 1 do
      ad, data, label, opcode, opland, comment, size = disasm.get_a_line(p)
      @main_win.setpos(cur, 0)
      if ad != nil
        if label then lab = ":" else lab = "" end
        if comment then comment = ";" + comment else comment = "" end
        str = "#{'%04X' % ad}\t#{data}\t#{label}#{lab}\t\t#{opcode}\t#{opland}\t#{comment}" 
      else
        str = ""
        size = 0
      end
      str << " " * (@sub_win.maxx - str.size) if @sub_win.maxx >= str.size
      if cur == @cur_line
        @main_win.standout
        @main_win.addstr str
        @main_win.standend
        @cur_addr = ad
        @cur_op = [opcode, opland]
      else
        @main_win.addstr str
      end 
      cur += 1
      p += size
    end
    @main_win.refresh
    
    if disasm.status != ""
      disp_sub(disasm, disasm.status)
      Curses.beep
      sleep 1
      disasm.status = ""
    end
    if disasm.size == 0
      disp_sub(disasm, %Q|no file|)
    else
      disp_sub(disasm, %Q|#{disasm.filename}(#{'%04X' % disasm.offset}-#{'%04X' % (disasm.size + disasm.offset - 1)})|)
    end
  end
 
  def disp_sub(dispasm, str)
    @sub_win.clear
    @sub_win.setpos(0, 0)
    @sub_win.standout
    @sub_win.addstr %Q|#{str}#{" " * (@sub_win.maxx - str.size)}|
    @sub_win.standend
    @sub_win.refresh
  end 

  def top_addr= (x)
    @top_addr = x
    update(@disasm)
  end

  def cur_line= (x)
    @cur_line = x
    update(@disasm)
  end

  def next
    if @cur_line < @max_line - 1
      @cur_line += 1
    else
      @top_addr = @disasm.next_ad(@top_addr)
    end
    update(@disasm)
  end

  def prev
    if @cur_line > 0
      @cur_line -= 1
    else
      @top_addr = @disasm.pre_ad(@top_addr)
    end
    update(@disasm)
  end

  def getch
    @main_win.getch
  end

  def getstr(prompt)
    buf = ""
    history_i = @history.size - 1
    loop do
      @cmd_win.clear
      @cmd_win.addstr prompt + buf
      Curses.curs_set(1)
      c = @cmd_win.getch
      case c
      when Curses::KEY_DOWN
        if (@history.size > 0) && (history_i < @history.size - 1)
          history_i += 1
          buf = @history[history_i]
        else
          buf = ""
        end
      when Curses::KEY_UP
        if (@history.size > 0) && (history_i >= 0)
          buf = @history[history_i]
          history_i -= 1 if history_i != 0
        end
      when Curses::KEY_BACKSPACE, Curses::KEY_DC
        buf = buf[0..-2]
      when 0x1b #esc
        buf = 0x1b
        break
      when 0x0a #"\n"
        @history.push buf
        break
      else
        buf <<= c
      end
    end
    @cmd_win.clear
    @cmd_win.refresh
    buf
  end
end

class Cmd
  def initialize
    @target = ARGV[0]
    @disasm = Disasm.new(@target)
    @hist_j = []

    Curses.init_screen
    Curses.cbreak
    Curses.noecho
    Curses.ESCDELAY = 100 #100msec
    Curses.curs_set(0)
    @window = Curses.stdscr
    @win = MainWin.new(@disasm, @window)
    @win.update(@disasm)
  end

  def main
    loop do
      @win.update(@disasm)
      c = @win.getch
      case c
      when ?q then exit
      when ?:
        x = @win.getstr(":")
        if x != 0x1b #esc
          if x =~ /^([0-9A-Fa-f]{1,4})$/
            x = x.to_i(16)
            if @disasm.in_range(x)
              @win.top_addr = x
            else
              @disasm.status = %Q|range err: jump to #{"%04X" % x}|
            end
          elsif @disasm.label.key(x)
            x = @disasm.label.key(x)
            if @disasm.in_range(x)
              @win.top_addr = x
            else
              @disasm.status = %Q|range err: jump to #{"%04X" % x}|
            end
          else
            @disasm.status = "error: invalid address #{x}"
          end
          @win.cur_line = 0
        end
      when Curses::KEY_UP, ?k
        @win.prev
      when Curses::KEY_DOWN, ?j
        @win.next
      when Curses::KEY_RIGHT, 0x1d #c-] jump
        cur_ad = @win.cur_addr
        cur_opcode, cur_opland = @win.cur_op
        @hist_j.push cur_ad
        cal_ad(cur_opcode, cur_opland)
        @win.cur_line = 0
      when Curses::KEY_LEFT, 0x14 #\C-t
        if @hist_j.size > 0
          @win.top_addr = @hist_j.pop
          @win.cur_line = 0
        end
      when ?b
        x = @win.getstr("DB:")
        if x != 0x1b #esc
          cur_ad = @win.cur_addr
          cur_opcode, cur_opland = @win.cur_op
          if x =~ /^(\d+)$/
            res = x.to_i
            @disasm.db[cur_ad] = res
          elsif x == "z"
            result = 0
            str = ""
            p = cur_ad
            while @disasm.data[p] != 0
              str << @disasm.data[p].chr
              p += 1
              result += 1
            end
            @disasm.db[cur_ad] = result + 1
            @disasm.comment[cur_ad] = str
          elsif x == "d"
            result = 0
            str = ""
            p = cur_ad
            while @disasm.data[p] != 0xd
              str << @disasm.data[p].chr
              p += 1
              result += 1
            end
            @disasm.db[cur_ad] = result + 1
            @disasm.comment[cur_ad] = str
          elsif x == ""
            @disasm.db.delete(cur_ad)
          end
        end
      when ?w
        x = @win.getstr("DW:")
        if x != 0x1b #esc
          cur_ad = @win.cur_addr
          cur_opcode, cur_opland = @win.cur_op
          if x =~ /^(\d+)$/
            res = x.to_i
            @disasm.dw[cur_ad] = res
          elsif x == ""
            @disasm.dw.delete(cur_ad)
          end
        end
      when ?l
        x = @win.getstr("LABEL:")
        if x != 0x1b #esc
          cur_ad = @win.cur_addr
          cur_opcode, cur_opland = @win.cur_op
          if x == "" then
            @disasm.label.delete(cur_ad)
          else
            @disasm.label[cur_ad] = x
          end
        end  
      when ?;
        x = @win.getstr("Comment:")
        if x != 0x1b #esc
          cur_ad = @win.cur_addr
          cur_opcode, cur_opland = @win.cur_op
          if x == ""
            @disasm.comment.delete(cur_ad)
          else
            @disasm.comment[cur_ad] = x
          end
        end
      when ?o
        x = @win.getstr("OFFSET:")
        if x != 0x1b #esc
          if x =~ /^([0-9A-Fa-f]+)$/
            res = x.to_i(16)
            @disasm.offset = res
            @win.top_addr = res
          end
        end
      when ?W
        @disasm.save
        @disasm.status = "cfg saved"
      when ?S
        @disasm.source_save
        @disasm.status = "source saved"
      when ?e
        @disasm.filename = @win.getstr("FileName:")
        @disasm.load
        @win.top_addr = @disasm.offset
      when Curses::KEY_RESIZE
        @win.resize(@window)
        @win.update(@disasm)
      when 0x1b #esc
        # nop
      when " "
        @win.cur_line = @win.max_line - 1
        @win.max_line.times do
          @win.next
        end
      else
        @disasm.status = "error key=#{c.inspect}"
      end
    end
    Curses.close_screen
  end
end

Cmd.new.main

