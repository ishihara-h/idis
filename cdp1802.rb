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
class Disasm
  def nemonic(p)
    x = []
    if @dw.has_key?(p)
      0.upto (@dw[p] - 1) do |i|
        x.push '%04X'%(@data[p + i] * 256 + @data[p + i + 1])
      end
      if @dw[p] == 1
        return ["DW", oplabel2(p), 2]
      else
        return ["DW", x.join(","), @dw[p] * 2]
      end
    end
    if @db.has_key?(p)
      0.upto (@db[p] - 1) do |i|
        x.push '%02X'% @data[p + i]
      end
      return ["DB", x.join(","), @db[p]]
    end

    hi = (@data[p] >> 4) & 0xf
    lo = @data[p] & 0xf
    case hi
    when 0 
      if lo == 0 then ["IDL", "", 1] else ["LDN", "%X" % lo, 1] end
    when 1 then ["INC", "R%X" % lo, 1]
    when 2 then ["DEC", "R%X" % lo, 1]
    when 3
      if lo == 8
        ["NBR", "", 1]
      else
        [case lo
         when 0 then "BR"
         when 1 then "BQ"
         when 2 then "BZ"
         when 3 then "BDF"
         when 4 then "B1"
         when 5 then "B2"
         when 6 then "B3"
         when 7 then "B4"
         when 9 then "BNQ"
         when 10 then "BNZ"
         when 11 then "BNF"
         when 12 then "BN1"
         when 13 then "BN2"
         when 14 then "BN3"
         when 15 then "BN4"
         end, oplabel1(p + 1), 2]
       end
    when 4 then ["LDA", "R%X" % lo, 1]
    when 5 then ["STR", "R%X" % lo, 1]
    when 6
      case lo
      when 0 then ["IRX", "", 1]
      when 8 then ["---", "", 1]
      when 1..7  then ["OUT", "%d" % lo, 1]
      when 9..15 then ["INP", "%d" % (lo % 8), 1]
      end
    when 7
      if lo < 12
        [case lo
         when 0 then "RET"
         when 1 then "DIS"
         when 2 then "LDXA"
         when 3 then "STXD"
         when 4 then "ADC"
         when 5 then "SDB"
         when 6 then "SHRC"
         when 7 then "SMB"
         when 8 then "SAV"
         when 9 then "MARK"
         when 10 then  "REQ"
         when 11 then  "SEQ"
         end, "", 1]
      else
        [case lo
         when 12 then "ADCI"
         when 13 then "SDBI"
         when 14 then "SHLC"
         when 15 then "SMBI"
         end, "%02X" % @data[p + 1], 2]
      end
    when 8 then ["GLO", "R%02X" % lo, 1]
    when 9 then ["GHI", "R%02X" % lo, 1]
    when 10 then ["PLO", "R%02X" % lo, 1]
    when 11 then ["PHI", "R%02X" % lo, 1]
    when 12
      if lo == 8
        ["NLBR", "", 1]
      elsif lo == 4
        ["NOP", "", 1]
      else
        [case lo
         when 0 then "LBR"
         when 1 then "LBQ"
         when 2 then "LBZ"
         when 3 then "LBDF"
         when 5 then "LSNQ"
         when 6 then "LSNZ"
         when 7 then "LSNF"
         when 9 then "LBNQ"
         when 10 then "LBNZ"
         when 11 then "LBNF"
         when 12 then "LSIE"
         when 13 then "LSQ"
         when 14 then "LSZ"
         when 15 then "LSDF"
         end, oplabel2(p + 1), 3]
      end
    when 13
      if lo == 4 #sep 4; dw address
        @dw[p + 1] = 1 
      end
      ["SEP", "R#{lo}", 1] 
    when 14 then ["SEX", "R%02X" % lo, 1]
    when 15
      if lo < 8
        [case lo
         when 0 then "LDX"
         when 1 then "OR"
         when 2 then "AND"
         when 3 then "XOR"
         when 4 then "ADD"
         when 5 then "SD"
         when 6 then "SHR"
         when 7 then "SM"
         end, "", 1]
      else
        [case lo
         when 8 then "LDI"
         when 9 then "ORI"
         when 10 then "ANI"
         when 11 then "XRI"
         when 12 then "ADI"
         when 13 then "SDI"
         when 14 then "SHL"
         when 15 then "SMI"
         end, "%02X" % @data[p + 1], 2]
      end
    end
  end

  private
  def oplabel1(p)
    n = @data[p]
    if @label.has_key?(p & 0xff00 + n)
      @label[p & 0xff00 + n]
    else
      "%02X" % n
    end
  end
  
  def oplabel2(p)
    n = @data[p] * 256 + @data[p + 1]
    if @label.has_key?(n)
      @label[n]
    else 
      "%04X" % n
    end
  end
end

class Cmd
  def cal_ad(cur_opcode, cur_opland) 
    if cur_opland =~ /^([0-9A-Fa-f]{1,4})$/
      ad = $1.to_i(16)
      if @disasm.in_range(ad)
        @win.top_addr = ad
      else
        @disasm.status = "range error #{cur_opland}"
      end
    elsif res = @disasm.label.find{|x| x[1] == cur_oplane}
      @win.top_addr =res[0]
    else
      @disasm.status = "error |#{cur_opland}|"
    end
  end
end


