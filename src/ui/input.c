#include "input.h"

#include <gba_input.h>
#include <gba_interrupt.h>
#include <gba_systemcalls.h>

static volatile u32 vblank_ticks;
static u32 last_change;

/* libgba's keysDown() and keysUp() RESET their state on read
 * (third_party/libgba/src/input.c:102-119). Calling input_pressed()
 * twice in the same frame would return the bits only the first time —
 * the second call gives 0. We hit this bug with SELECT when it lived
 * next to a START handler in the same loop.
 *
 * Solution: drain the consume-on-read queues EXACTLY once per
 * input_poll() and expose idempotent reads from the cache. */
static u16 cached_pressed;
static u16 cached_released;

static void on_vblank(void) { vblank_ticks++; }

void input_init(void) {
    irqInit();
    irqSet(IRQ_VBLANK, on_vblank);
    irqEnable(IRQ_VBLANK);
    vblank_ticks = 0;
    last_change = 0;
    cached_pressed = 0;
    cached_released = 0;
}

void input_poll(void) {
    u16 prev = keysHeld();
    scanKeys();
    cached_pressed  = keysDown();   /* drain and cache */
    cached_released = keysUp();     /* same */
    if (keysHeld() != prev) {
        last_change = vblank_ticks;
    }
}

u16 input_pressed(void)  { return cached_pressed; }
u16 input_held(void)     { return keysHeld(); }
u16 input_released(void) { return cached_released; }

u32 input_last_change_tick(void) { return last_change; }

u16 input_wait_any(void) {
    for (;;) {
        VBlankIntrWait();
        input_poll();
        u16 p = input_pressed();
        if (p) return p;
    }
}
