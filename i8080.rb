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
        x.push '%04X'%(@data[p + i] + @data[p + i + 1] * 256)
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

    op1 = (@data[p] >> 6) & 0x3
    op2 = (@data[p] >> 3) & 0x7
    op3 = @data[p] & 0x7
    case op1
    when 0 
      case op3
      when 0
        [%w(NOP UNDEF UNDEF UNDEF UNDEF UNDEF UNDEF UNDEF)[op2], "", 1]
      when 1
        if (op2 & 1) == 0
          ["LXI", %Q|#{reg16(op2 >> 1)},#{imm16(p)}|, 3]
        else
          ["DAD", %Q|#{reg16(op2 >> 1)}|, 1]
        end
      when 2
        if (op2 & 1) == 0
          if (op2 >> 1) == 2
            ["SHLD", imm16(p), 3]
          elsif (op2 >> 1) == 3
            ["STA", imm16(p), 3]
          else
            ["STAX", reg16(op2 >> 1), 1]
          end
        else
          if (op2 >> 1) == 2
            ["LHLD", imm16(p), 3]
          elsif (op2 >> 1) == 3
            ["LDA", imm16(p), 3]
          else
            ["LDAX", reg16(op2 >> 1), 1]
          end
        end
      when 3
        if (op2 & 1) == 0
          ["INX", reg16(op2 >> 1), 1]
        else
          ["DCR", reg16(op2 >> 1), 1]
        end
      when 4
        ["INR", reg8(op2), 1]
      when 5
        ["DCR", reg8(op2), 1]
      when 6
        ["MVI", %Q|#{reg8(op2)},#{imm8(p)}|, 2] 
      when 7
        [%w(RLC RRC RAL RAR DAA CMA STC CMC)[op2], "", 1]
      end
    when 1
      if op2 == 6 && op3 == 6
        ["HLT", "", 1]
      else
        ["MOV", "#{reg8(op2)},#{reg8(op3)}", 1]
      end
    when 2
      [%w(ADD ADC SUB SBB ANA XRA ORA CMP)[op2], reg8(op3), 1]
    when 3
      case op3
      when 0
        [%w(RNZ RZ RNC RC RPO RPE RP RM)[op2], "", 1]
      when 1
        if (op2 & 1) == 0
          ["POP", reg16_psw(op2 >> 1), 1]
        else
          [%w(RET UNDEF PCHL SPHL)[op2 >> 1], "", 1]
        end
      when 2
        [%w(JNZ JZ JNC JC JPO JPE JP JM)[op2], oplabel2(p), 3]
      when 3
        case op2
        when 0
          ["JMP", oplabel2(p), 3]
        when 1
          ["UNDEF", imm16(p), 3]
        when 2
          ["OUT", imm8(p), 2]
        when 3
          ["IN", imm8(p), 2]
        when 4
          ["XTHL", "", 1]
        when 5 
          ["XCHG", "", 1]
        when 6
          ["DI", "", 1]
        when 7
          ["EI", "", 1]
        end
      when 4
        [%w(CNZ CZ CNC CC CPO CPE CP CM)[op2], oplabel2(p), 3]
      when 5
        if (op2 & 1) == 0
          ["PUSH", reg16_psw(op2 >> 1), 1]
        else
          [%w(CALL UNDEF UNDEF UNDEF)[op2 >> 1], oplabel2(p), 3]
        end
      when 6
        [%w(ADI ACI SUI SBI ANI XRI ORI CPI)[op2], imm8(p), 2]
      when 7
        ["RST", "%d" % op2, 1]
      end
    end
  end

  def reg8(r)
    %w(B C D E H L M A)[r]
  end

  def reg16(r)
    %w(B D H SP)[r]
  end

  def reg16_psw(r)
    %w(B D H PSW)[r]
  end

  def imm8(p)
    x = @data[p + 1]
    if x > 0x9f
      "%03XH" % x
    else
      "%02XH" % x
    end
  end

  def imm16(p)
    x = @data[p + 1] + @data[p + 2] * 256
    if x > 0x9fff
      "%05XH" % x
    else
      "%04XH" % x
    end
  end

  private
  def oplabel1(p)
    n = @data[p]
    if n > 127
      n = n - 256
    end
    if @label.has_key?(p + n)
      @label[p + n]
    else
      "%02X" % n
    end
  end
  
  def oplabel2(p)
    n = @data[p + 1] + @data[p + 2] * 256
    if @label.has_key?(n)
      @label[n]
    elsif n > 0x9fff
      "%05XH" % n
    else
      "%04XH" % n
    end
  end
end

class Cmd
  def cal_ad(cur_opcode, cur_opland) 
    if cur_opland =~ /^([0-9][0-9A-Fa-f]{0,4})H/
      ad = $1.to_i(16)
      if %w(BR BQ BZ BDF B1 B2 B3 B4 BBQ BNZ BNF BN1 BN2 BN3 BN4).include?(cur_opcode)
        ad += cur_ad & 0xff00
      end
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
