#include "input.h"

#include <gba_input.h>
#include <gba_interrupt.h>
#include <gba_systemcalls.h>

static volatile u32 vblank_ticks;
static u32 last_change;

static void on_vblank(void) { vblank_ticks++; }

void input_init(void) {
    irqInit();
    irqSet(IRQ_VBLANK, on_vblank);
    irqEnable(IRQ_VBLANK);
    vblank_ticks = 0;
    last_change = 0;
}

void input_poll(void) {
    u16 prev = keysHeld();
    scanKeys();
    if (keysHeld() != prev) {
        last_change = vblank_ticks;
    }
}

u16 input_pressed(void)  { return keysDown(); }
u16 input_held(void)     { return keysHeld(); }
u16 input_released(void) { return keysUp(); }

u32 input_last_change_tick(void) { return last_change; }

u16 input_wait_any(void) {
    for (;;) {
        VBlankIntrWait();
        input_poll();
        u16 p = input_pressed();
        if (p) return p;
    }
}
