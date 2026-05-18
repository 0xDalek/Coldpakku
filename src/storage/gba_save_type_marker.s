@ Marker so mGBA / flashcarts detect that the ROM uses 32 KB SRAM.
@ The string must appear somewhere in the binary; .ascii puts it in .rodata.

    .section .rodata
    .align 2
    .global gba_save_type_marker
gba_save_type_marker:
    .ascii "SRAM_V113\0"
