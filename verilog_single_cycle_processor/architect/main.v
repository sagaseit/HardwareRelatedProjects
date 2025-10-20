// srcA and srcB are the two 32-bit inputs to the ALU
// alu_control is a 3-bit control signal that determines the operation to be performed
// alu_out is the 32-bit output of the ALU
// zero is 1 when alu_out == 0 that is used by Control Unit
// compare = 1 when srcA == srcB
module alu32(
    input [31:0] srcA, srcB,
    input [2:0] alu_control,
    output reg [31:0] alu_out,
    output alu_compare,
    output alu_zero);

  always @(*) begin //nastava zmena hodnot
    case (alu_control)
      3'b000: alu_out = srcA + srcB; // 000 - add      
      3'b001: alu_out = srcA - srcB; // 001 - sub
      3'b010: alu_out = srcA & srcB; // 010 - and
      3'b011: alu_out = srcA >> srcB[4:0]; // 011 - srl
      default: alu_out = 0;
    endcase
  end

  assign alu_compare = (srcA == srcB);
  assign alu_zero = (alu_out == 0);

endmodule

// opcode - 7-bit opcode from instruction
// funct3 - 3-bit funct3 from instruction
// funct7 - 7-bit funct7 from instruction

module control_unit(
    input  [6:0] opcode,
    input  [2:0] funct3,
    input  [6:0] funct7,
    output reg       BranchBeq,
    output reg       BranchJal,
    output reg       BranchJalr,
    output reg       RegWrite,
    output reg       MemToReg,
    output reg       MemWrite,
    output reg [2:0] ALUControl,
    output reg       ALUSrc,
    output reg [1:0] immControl);

always @(*)
begin
    case (opcode)
    7'b0110011:
    7'b0010011:
    7'b0100011:
    7'b1100011:
    7'b0000011:
    7'b0110111:
    7'b1101111:
    7'b1100111:
    7'b0001011:


    endcase
end

endmodule
