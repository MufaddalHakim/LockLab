`default_nettype none

module c17 (
    input  wire N1,
    input  wire N2,
    input  wire N3,
    input  wire N6,
    input  wire N7,
    output wire N22,
    output wire N23
);
    wire N10;
    wire N11;
    wire N16;
    wire N19;

    nand g1(N10, N1, N3);
    nand g2(N11, N3, N6);
    nand g3(N16, N2, N11);
    nand g4(N19, N11, N7);
    nand g5(N22, N10, N16);
    nand g6(N23, N16, N19);
endmodule

`default_nettype wire
