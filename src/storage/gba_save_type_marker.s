@ Marcador para que mGBA / flashcarts detecten que la ROM usa SRAM 32 KB.
@ La cadena debe aparecer en algún sitio del binario; .ascii la deja en .rodata.

    .section .rodata
    .align 2
    .global gba_save_type_marker
gba_save_type_marker:
    .ascii "SRAM_V113\0"
